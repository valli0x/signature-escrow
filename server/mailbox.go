package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/valli0x/signature-escrow/auth"
	"github.com/valli0x/signature-escrow/storage"
)

const mailboxPrefix = "mailbox/"

// Message represents a mailbox message between paired participants.
type Message struct {
	ID        string          `json:"id"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	PairID    string          `json:"pair_id"`
	Type      string          `json:"type"` // "keygen_request", "keygen_accept", etc.
	Body      json.RawMessage `json:"body"`
	CreatedAt int64           `json:"created_at"`
}

type MailboxSendRequest struct {
	To     string          `json:"to"`
	PairID string          `json:"pair_id"`
	Type   string          `json:"type"`
	Body   json.RawMessage `json:"body"`
}

type MailboxSendResponse struct {
	ID string `json:"id"`
}

type MailboxPendingResponse struct {
	Messages []Message `json:"messages"`
}

type MailboxAckRequest struct {
	ID string `json:"id"`
}

func messageID(from, to string, ts int64) string {
	return fmt.Sprintf("%s_%s_%d",
		strings.ToLower(strings.TrimPrefix(from, "0x")),
		strings.ToLower(strings.TrimPrefix(to, "0x")),
		ts,
	)
}

func storeMessage(stor storage.Storage, msg *Message) error {
	data, err := cbor.Marshal(msg)
	if err != nil {
		return err
	}

	// Store the message
	if err := stor.Put(context.Background(), mailboxPrefix+msg.ID, data); err != nil {
		return err
	}

	// Add to recipient's index
	return addToIndex(stor, mailboxPrefix+"inbox/"+strings.ToLower(msg.To), msg.ID)
}

func loadMessage(stor storage.Storage, id string) (*Message, error) {
	data, err := stor.Get(context.Background(), mailboxPrefix+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	msg := &Message{}
	if err := cbor.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func deleteMessage(stor storage.Storage, id, recipient string) error {
	// Delete the message
	if err := stor.Delete(context.Background(), mailboxPrefix+id); err != nil {
		return err
	}

	// Remove from recipient's index
	return removeFromIndex(stor, mailboxPrefix+"inbox/"+strings.ToLower(recipient), id)
}

// removeFromIndex removes a message ID from an index list.
func removeFromIndex(stor storage.Storage, key, msgID string) error {
	data, err := stor.Get(context.Background(), key)
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}

	var ids []string
	if err := cbor.Unmarshal(data, &ids); err != nil {
		return err
	}

	filtered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != msgID {
			filtered = append(filtered, id)
		}
	}

	if len(filtered) == 0 {
		return stor.Delete(context.Background(), key)
	}

	newData, err := cbor.Marshal(filtered)
	if err != nil {
		return err
	}
	return stor.Put(context.Background(), key, newData)
}

func loadInbox(stor storage.Storage, address string) ([]string, error) {
	data, err := stor.Get(context.Background(), mailboxPrefix+"inbox/"+strings.ToLower(address))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var ids []string
	if err := cbor.Unmarshal(data, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// Handlers

func (s *Server) mailboxSend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req MailboxSendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.To == "" || req.PairID == "" || req.Type == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("to, pair_id and type are required"))
			return
		}

		from := auth.AddressFromContext(r.Context())
		to := strings.ToLower(req.To)

		// Verify sender belongs to the pair
		pair, err := loadPair(s.stor, req.PairID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if pair == nil {
			respondError(w, http.StatusNotFound, fmt.Errorf("pair not found"))
			return
		}

		isInitiator := strings.EqualFold(pair.Initiator, from)
		isPartner := strings.EqualFold(pair.Partner, from)
		if !isInitiator && !isPartner {
			respondError(w, http.StatusForbidden, fmt.Errorf("you are not part of this pair"))
			return
		}

		// Verify recipient is the other member of the pair
		recipientInPair := strings.EqualFold(pair.Initiator, to) || strings.EqualFold(pair.Partner, to)
		if !recipientInPair {
			respondError(w, http.StatusBadRequest, fmt.Errorf("recipient is not part of this pair"))
			return
		}

		now := time.Now().UnixNano()
		msg := &Message{
			ID:        messageID(from, to, now),
			From:      from,
			To:        to,
			PairID:    req.PairID,
			Type:      req.Type,
			Body:      req.Body,
			CreatedAt: now,
		}

		if err := storeMessage(s.stor, msg); err != nil {
			s.logger.Error("failed to store message", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to send message"))
			return
		}

		s.logger.Info("mailbox message sent", "from", from, "to", to, "type", req.Type)

		respondOk(w, MailboxSendResponse{ID: msg.ID})
	}
}

func (s *Server) mailboxPending() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		myAddr := auth.AddressFromContext(r.Context())

		ids, err := loadInbox(s.stor, myAddr)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		messages := make([]Message, 0)
		for _, id := range ids {
			msg, err := loadMessage(s.stor, id)
			if err != nil || msg == nil {
				continue
			}
			messages = append(messages, *msg)
		}

		respondOk(w, MailboxPendingResponse{Messages: messages})
	}
}

func (s *Server) mailboxAck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req MailboxAckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.ID == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("message id is required"))
			return
		}

		myAddr := auth.AddressFromContext(r.Context())

		// Verify the message belongs to this user
		msg, err := loadMessage(s.stor, req.ID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if msg == nil {
			respondError(w, http.StatusNotFound, fmt.Errorf("message not found"))
			return
		}
		if !strings.EqualFold(msg.To, myAddr) {
			respondError(w, http.StatusForbidden, fmt.Errorf("not your message"))
			return
		}

		if err := deleteMessage(s.stor, req.ID, myAddr); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete message"))
			return
		}

		respondOk(w, nil)
	}
}
