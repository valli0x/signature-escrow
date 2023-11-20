package txwithdrawal

type TxWithdrawal struct {
	IDPart    string `json:"id_part"`
	TokenType string `json:"token_type"`
	Address   string `json:"address"`
	Value     int64  `json:"value"`
	Hash      string `json:"hash"`
	IncSig    string `json:"inc_sig"`
}

