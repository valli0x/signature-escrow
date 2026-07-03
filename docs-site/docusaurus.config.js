// @ts-check
const {themes} = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'mpcoven',
  tagline: 'MPC 2-of-2 signature-escrow wallet',
  favicon: 'img/favicon.svg',
  url: 'https://mpcoven.net',
  baseUrl: '/docs/',
  organizationName: 'valli0x',
  projectName: 'signature-escrow',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',
  i18n: {defaultLocale: 'en', locales: ['en']},

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/', // docs at /docs
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/valli0x/signature-escrow/tree/main/',
        },
        blog: false,
        theme: {customCss: require.resolve('./src/css/custom.css')},
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/social-card.png',
      colorMode: {defaultMode: 'dark', respectPrefersColorScheme: true},
      navbar: {
        title: 'mpcoven',
        logo: {alt: 'mpcoven', src: 'img/logo.svg'},
        items: [
          {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Documentation'},
          {href: 'https://mpcoven.net/app/', label: 'App', position: 'right'},
          {href: 'https://mpcoven.net/api/swagger/index.html', label: 'API', position: 'right'},
          {href: 'https://github.com/valli0x/signature-escrow', label: 'GitHub', position: 'right'},
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {label: 'Overview', to: '/'},
              {label: 'Architecture', to: '/architecture'},
              {label: 'MPC co-signing', to: '/mpc-cosigning'},
              {label: 'Atomic swap', to: '/escrow-swap'},
            ],
          },
          {
            title: 'More',
            items: [
              {label: 'Open the app', href: 'https://mpcoven.net/app/'},
              {label: 'API (Swagger)', href: 'https://mpcoven.net/api/swagger/index.html'},
              {label: 'GitHub', href: 'https://github.com/valli0x/signature-escrow'},
            ],
          },
        ],
        copyright: `© ${new Date().getFullYear()} mpcoven. MIT-licensed.`,
      },
      prism: {theme: themes.github, darkTheme: themes.dracula},
    }),
};

module.exports = config;
