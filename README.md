# Google Ads MCP (somente leitura)

Servidor MCP remoto que conecta o Google Ads ao Claude. Roda como Cloudflare Worker, sem dependências.

- Login com Google (OAuth). Só os e-mails em `ALLOWED_EMAILS` entram.
- Só consultas. Não altera nada nas contas.
- Ferramentas: `list_accounts`, `campaign_performance`, `daily_performance`, `keyword_performance`, `search_terms`, `ad_performance`, `run_gaql`.

## Configuração

1. **Google Cloud** (no projeto aprovado para a Google Ads API):
   - Ative a Google Ads API.
   - Publique a tela de consentimento.
   - Crie um cliente OAuth do tipo **Aplicativo da Web** com o URI de redirecionamento `https://<worker>.workers.dev/callback`.
2. **Cloudflare**: importe este repositório em Workers. Em *Configurações → Variáveis e segredos*, crie os segredos:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `ENCRYPTION_KEY` (texto aleatório com 32 ou mais caracteres)
3. **Claude**: em Configurações → Conectores → Adicionar conector personalizado, informe a URL `https://<worker>.workers.dev/mcp`.

As variáveis comuns ficam em `wrangler.jsonc`:

- `ALLOWED_EMAILS`
- `ADS_API_VERSION`
- `LOGIN_CUSTOMER_ID` (opcional: ID da conta MCC)

## Teste local

`node test/flow.test.mjs` roda o fluxo OAuth e as ferramentas com o Google simulado.
