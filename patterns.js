/**
 * ==============================================================================
 * ACKNOWLEDGMENTS & CREDITS
 * ==============================================================================
 * The regex patterns in this file were curated, adapted, and inspired by the 
 * incredible research from the following open-source security tools:
 * 
 * 1. GitLeaks (https://github.com/gitleaks/gitleaks) - MIT License
 * 2. TruffleHog (https://github.com/trufflesecurity/trufflehog) - AGPL-3.0
 * 3. Yelp detect-secrets (https://github.com/Yelp/detect-secrets) - Apache 2.0
 * 
 * We deeply respect their work in making the internet a safer place.
 * ==============================================================================
 */

// Each pattern has: name, regex, redaction placeholder, and category

const PATTERN_CATEGORIES = {
    cloud: { name: "Cloud Providers", description: "AWS, GCP, Azure credentials", enabled: true },
    vcs: { name: "Version Control", description: "GitHub, GitLab, Bitbucket tokens", enabled: true },
    communication: { name: "Communication", description: "Slack, Discord, Telegram, Teams webhooks & tokens", enabled: true },
    payment: { name: "Payment", description: "Stripe, PayPal, Square, Plaid keys", enabled: true },
    database: { name: "Database", description: "Connection strings with credentials", enabled: true },
    privateKeys: { name: "Private Keys", description: "RSA, SSH, PGP private keys", enabled: true },
    apiKeys: { name: "API Keys", description: "Various service API keys", enabled: true },
    ci_cd: { name: "CI/CD", description: "CircleCI, Drone, Travis, Azure DevOps tokens", enabled: true },
    ai_ml: { name: "AI & ML", description: "OpenAI, Anthropic, HuggingFace, Replicate keys", enabled: true },
    generic: { name: "Generic Secrets", description: "Passwords, tokens in assignments", enabled: true },
    entropy: { name: "High Entropy", description: "Suspicious high-entropy strings", enabled: true }
};

const SECRET_PATTERNS = [
    // AWS (cloud)
    {
        name: "AWS Access Key ID",
        regex: /(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}/g,
        redact: "[AWS_ACCESS_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "AWS Secret Access Key",
        regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretaccesskey)[\s]*[=:][\s]*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        redact: "[AWS_SECRET_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "AWS Session Token",
        regex: /(?:aws_session_token|sessiontoken)[\s]*[=:][\s]*['"]?([A-Za-z0-9/+=]{100,})['"]?/gi,
        redact: "[AWS_SESSION_TOKEN_REDACTED]",
        category: "cloud"
    },

    // GitHub (vcs) — consolidated per GitLeaks patterns
    {
        name: "GitHub Personal Access Token (Classic)",
        regex: /ghp_[A-Za-z0-9_]{36,}/g,
        redact: "[GITHUB_PAT_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitHub OAuth Access Token",
        regex: /gho_[A-Za-z0-9_]{36,}/g,
        redact: "[GITHUB_OAUTH_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitHub User-to-Server Token",
        regex: /ghu_[A-Za-z0-9_]{36,}/g,
        redact: "[GITHUB_U2S_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitHub Server-to-Server Token",
        regex: /ghs_[A-Za-z0-9_]{36,}/g,
        redact: "[GITHUB_S2S_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitHub App Refresh Token",
        regex: /ghr_[A-Za-z0-9_]{36,}/g,
        redact: "[GITHUB_REFRESH_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitHub Fine-grained PAT",
        regex: /github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}/g,
        redact: "[GITHUB_FINE_GRAINED_TOKEN_REDACTED]",
        category: "vcs"
    },

    // GitLab (vcs) — expanded per GitLeaks
    {
        name: "GitLab Personal Access Token",
        regex: /glpat-[A-Za-z0-9\-_]{20,}/g,
        redact: "[GITLAB_PAT_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Pipeline Trigger Token",
        regex: /glptt-[A-Za-z0-9]{20,}/g,
        redact: "[GITLAB_PIPELINE_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Runner Registration Token",
        regex: /GR1348941[A-Za-z0-9\-_]{20,}/g,
        redact: "[GITLAB_RUNNER_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Deploy Token",
        regex: /gldt-[A-Za-z0-9\-_]{20,}/g,
        redact: "[GITLAB_DEPLOY_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab CI Build Token",
        regex: /glcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20,}/g,
        redact: "[GITLAB_CI_BUILD_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Incoming Mail Token",
        regex: /glimt-[A-Za-z0-9\-_]{25,}/g,
        redact: "[GITLAB_INCOMING_MAIL_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Agent Token",
        regex: /glagent-[A-Za-z0-9\-_]{50,}/g,
        redact: "[GITLAB_AGENT_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab Feed Token",
        regex: /glft-[A-Za-z0-9\-_]{20,}/g,
        redact: "[GITLAB_FEED_TOKEN_REDACTED]",
        category: "vcs"
    },
    {
        name: "GitLab OAuth App Secret",
        regex: /gloas-[A-Za-z0-9\-_]{64,}/g,
        redact: "[GITLAB_OAUTH_SECRET_REDACTED]",
        category: "vcs"
    },

    // Bitbucket (vcs)
    {
        name: "Bitbucket App Password",
        regex: /(?:bitbucket)(?:[_\-\s]*(?:app)?[_\-\s]*(?:password|secret|key|token))[\s]*[=:][\s]*['"]?([A-Za-z0-9]{20,})['"]?/gi,
        redact: "[BITBUCKET_APP_PASSWORD_REDACTED]",
        category: "vcs"
    },

    // Google/GCP (cloud)
    {
        name: "Google API Key",
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        redact: "[GOOGLE_API_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "Google OAuth Client Secret",
        regex: /(?:client_secret|clientsecret)[\s]*[=:][\s]*['"]?([A-Za-z0-9\-_]{24})['"]?/gi,
        redact: "[GOOGLE_OAUTH_SECRET_REDACTED]",
        category: "cloud"
    },
    {
        name: "GCP Service Account Key",
        regex: /"private_key"[\s]*:[\s]*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+-----END (?:RSA )?PRIVATE KEY-----\\n"/g,
        redact: '"private_key": "[GCP_SERVICE_ACCOUNT_KEY_REDACTED]"',
        category: "cloud"
    },

    // IBM / SoftLayer (cloud) — from detect-secrets
    {
        name: "IBM Cloud IAM Key",
        regex: /(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud)[_\-]*(?:api)?[_\-]*(?:key|token|pwd|pass|password)?[\s]*[=:][\s]*['"]?([a-zA-Z0-9_\-]{44})(?![\w\-])['"]?/gi,
        redact: "[IBM_CLOUD_IAM_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "IBM Cloudant API Key",
        regex: /(?:cloudant|cl|clou)[_\-]*(?:api)?[_\-]*(?:key|pwd|pw|password|pass|token)[\s]*[=:][\s]*['"]?([a-z]{24})['"]?/gi,
        redact: "[IBM_CLOUDANT_API_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "IBM Cloudant Password",
        regex: /(?:cloudant|cl|clou)[_\-]*(?:api)?[_\-]*(?:key|pwd|pw|password|pass|token)[\s]*[=:][\s]*['"]?([0-9a-f]{64})['"]?/gi,
        redact: "[IBM_CLOUDANT_PASSWORD_REDACTED]",
        category: "cloud"
    },
    {
        name: "SoftLayer API Key",
        regex: /(?:softlayer|sl)[_\-]*(?:api)?[_\-]*(?:key|pwd|password|pass|token)[\s]*[=:][\s]*['"]?([a-z0-9]{64})['"]?/gi,
        redact: "[SOFTLAYER_API_KEY_REDACTED]",
        category: "cloud"
    },

    // Azure (cloud)
    {
        name: "Azure Storage Account Key",
        regex: /(?:DefaultEndpointsProtocol|AccountKey)=[^;\s"']+/gi,
        redact: "[AZURE_STORAGE_KEY_REDACTED]",
        category: "cloud"
    },
    {
        name: "Azure AD Client Secret",
        regex: /(?:azure|ad|aad)(?:[_\-\s]*(?:client)?[_\-\s]*secret)[\s]*[=:][\s]*['"]?([A-Za-z0-9~.\-_]{34,})['"]?/gi,
        redact: "[AZURE_CLIENT_SECRET_REDACTED]",
        category: "cloud"
    },

    // Slack (communication) — expanded per GitLeaks
    {
        name: "Slack Bot Token",
        regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
        redact: "[SLACK_BOT_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Legacy Bot Token",
        regex: /xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}/g,
        redact: "[SLACK_LEGACY_BOT_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack User Token",
        regex: /xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}/g,
        redact: "[SLACK_USER_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Legacy Token",
        regex: /xox[os]-\d+-\d+-\d+-[a-fA-F\d]+/g,
        redact: "[SLACK_LEGACY_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Legacy Workspace Token",
        regex: /xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}/g,
        redact: "[SLACK_WORKSPACE_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Config Access Token",
        regex: /xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}/gi,
        redact: "[SLACK_CONFIG_ACCESS_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Config Refresh Token",
        regex: /xoxe-\d-[A-Z0-9]{146}/gi,
        redact: "[SLACK_CONFIG_REFRESH_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack Webhook URL",
        regex: /https?:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{43,56}/g,
        redact: "[SLACK_WEBHOOK_REDACTED]",
        category: "communication"
    },
    {
        name: "Slack App Token",
        regex: /xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+/gi,
        redact: "[SLACK_APP_TOKEN_REDACTED]",
        category: "communication"
    },

    // Discord (communication)
    {
        name: "Discord Bot Token",
        regex: /(?:discord|bot)[\s_\-]*token[\s]*[=:][\s]*['"]?([A-Za-z0-9._-]{50,})['"]?/gi,
        redact: "[DISCORD_BOT_TOKEN_REDACTED]",
        category: "communication"
    },
    {
        name: "Discord Webhook URL",
        regex: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
        redact: "[DISCORD_WEBHOOK_REDACTED]",
        category: "communication"
    },

    // Telegram (communication) — from GitLeaks
    {
        name: "Telegram Bot API Token",
        regex: /[0-9]{5,16}:A[a-zA-Z0-9_\-]{34}/g,
        redact: "[TELEGRAM_BOT_TOKEN_REDACTED]",
        category: "communication"
    },

    // Microsoft Teams (communication) — from GitLeaks
    {
        name: "Microsoft Teams Webhook",
        regex: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9-]+@[a-z0-9-]+\/IncomingWebhook\/[a-z0-9]+\/[a-z0-9-]+/gi,
        redact: "[TEAMS_WEBHOOK_REDACTED]",
        category: "communication"
    },

    // Stripe (payment) — consolidated per GitLeaks
    {
        name: "Stripe Secret / Restricted Key",
        regex: /(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}/g,
        redact: "[STRIPE_SECRET_KEY_REDACTED]",
        category: "payment"
    },
    {
        name: "Stripe Publishable Key",
        regex: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,
        redact: "[STRIPE_PUBLISHABLE_KEY_REDACTED]",
        category: "payment"
    },

    // PayPal (payment)
    {
        name: "PayPal Client Secret",
        regex: /(?:paypal)(?:[_\-\s]*(?:client)?[_\-\s]*secret)[\s]*[=:][\s]*['"]?([A-Za-z0-9\-_]{40,})['"]?/gi,
        redact: "[PAYPAL_CLIENT_SECRET_REDACTED]",
        category: "payment"
    },

    // Square (payment) — improved per GitLeaks
    {
        name: "Square Access Token",
        regex: /(?:EAAA|sq0atp-)[\w-]{22,60}/g,
        redact: "[SQUARE_ACCESS_TOKEN_REDACTED]",
        category: "payment"
    },
    {
        name: "Square OAuth Secret",
        regex: /sq0csp-[A-Za-z0-9\-_]{43}/g,
        redact: "[SQUARE_OAUTH_SECRET_REDACTED]",
        category: "payment"
    },

    // Plaid (payment) — from GitLeaks
    {
        name: "Plaid API Token",
        regex: /access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
        redact: "[PLAID_API_TOKEN_REDACTED]",
        category: "payment"
    },

    // Twilio (apiKeys)
    {
        name: "Twilio Account SID",
        regex: /AC[a-f0-9]{32}/g,
        redact: "[TWILIO_ACCOUNT_SID_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Twilio Auth Token",
        regex: /(?:twilio)(?:[_\-\s]*(?:auth)?[_\-\s]*token)[\s]*[=:][\s]*['"]?([a-f0-9]{32})['"]?/gi,
        redact: "[TWILIO_AUTH_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // SendGrid (apiKeys)
    {
        name: "SendGrid API Key",
        regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
        redact: "[SENDGRID_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Mailchimp (apiKeys)
    {
        name: "Mailchimp API Key",
        regex: /[a-f0-9]{32}-us[0-9]{1,2}/g,
        redact: "[MAILCHIMP_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // NPM (apiKeys)
    {
        name: "NPM Access Token",
        regex: /npm_[A-Za-z0-9]{36}/g,
        redact: "[NPM_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // PyPI (apiKeys)
    {
        name: "PyPI API Token",
        regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/g,
        redact: "[PYPI_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Heroku (apiKeys)
    {
        name: "Heroku API Key",
        regex: /(?:heroku)(?:[_\-\s]*(?:api)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
        redact: "[HEROKU_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Shopify (apiKeys) — expanded per GitLeaks
    {
        name: "Shopify Access Token",
        regex: /shpat_[a-fA-F0-9]{32}/g,
        redact: "[SHOPIFY_ACCESS_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Shopify Custom App Token",
        regex: /shpca_[a-fA-F0-9]{32}/g,
        redact: "[SHOPIFY_CUSTOM_APP_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Shopify Private App Token",
        regex: /shppa_[a-fA-F0-9]{32}/g,
        redact: "[SHOPIFY_PRIVATE_APP_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Shopify Shared Secret",
        regex: /shpss_[a-fA-F0-9]{32}/g,
        redact: "[SHOPIFY_SHARED_SECRET_REDACTED]",
        category: "apiKeys"
    },

    // Private Keys (privateKeys)
    {
        name: "RSA Private Key",
        regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
        redact: "[RSA_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "OpenSSH Private Key",
        regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
        redact: "[OPENSSH_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "PGP Private Key",
        regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
        redact: "[PGP_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "EC Private Key",
        regex: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
        redact: "[EC_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "DSA Private Key",
        regex: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
        redact: "[DSA_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "Generic Private Key",
        regex: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g,
        redact: "[PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },
    {
        name: "Encrypted Private Key",
        regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----/g,
        redact: "[ENCRYPTED_PRIVATE_KEY_REDACTED]",
        category: "privateKeys"
    },

    // JWT (apiKeys)
    {
        name: "JSON Web Token",
        regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
        redact: "[JWT_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Database Connection Strings (database)
    {
        name: "PostgreSQL Connection String",
        regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
        redact: "[POSTGRESQL_CONNECTION_REDACTED]",
        category: "database"
    },
    {
        name: "MySQL Connection String",
        regex: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/gi,
        redact: "[MYSQL_CONNECTION_REDACTED]",
        category: "database"
    },
    {
        name: "MongoDB Connection String",
        regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
        redact: "[MONGODB_CONNECTION_REDACTED]",
        category: "database"
    },
    {
        name: "Redis Connection String",
        regex: /redis:\/\/[^:]*:[^@]+@[^\s"']+/gi,
        redact: "[REDIS_CONNECTION_REDACTED]",
        category: "database"
    },

    // Artifactory (ci_cd) — from detect-secrets
    {
        name: "Artifactory API Token",
        regex: /(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$)/g,
        redact: "[ARTIFACTORY_API_TOKEN_REDACTED]",
        category: "ci_cd"
    },
    {
        name: "Artifactory Password",
        regex: /(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$)/g,
        redact: "[ARTIFACTORY_PASSWORD_REDACTED]",
        category: "ci_cd"
    },

    // Generic Password Patterns (generic)
    {
        name: "Password in Assignment",
        regex: /(?:password|passwd|pwd|secret)[\s]*[=:][\s]*['"]([^'"]{8,})['"](?!\s*[,}][\s]*\/\/)/gi,
        redact: '"[PASSWORD_REDACTED]"',
        category: "generic"
    },
    {
        name: "API Key in Assignment",
        regex: /(?:api[_\-]?key|apikey|api[_\-]?secret)[\s]*[=:][\s]*['"]([A-Za-z0-9\-_]{16,})['"](?!\s*[,}][\s]*\/\/)/gi,
        redact: '"[API_KEY_REDACTED]"',
        category: "generic"
    },
    {
        name: "Auth Token in Assignment",
        regex: /(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token)[\s]*[=:][\s]*['"]([A-Za-z0-9\-_]{16,})['"](?!\s*[,}][\s]*\/\/)/gi,
        redact: '"[AUTH_TOKEN_REDACTED]"',
        category: "generic"
    },

    // Terraform/Infrastructure (cloud)
    {
        name: "Terraform Variable Secret",
        regex: /variable\s+"[^"]*(?:secret|password|key|token)[^"]*"\s*\{[^}]*default\s*=\s*"([^"]+)"/gi,
        redact: '"[TERRAFORM_SECRET_REDACTED]"',
        category: "cloud"
    },

    // Docker (cloud)
    {
        name: "Docker Registry Auth",
        regex: /"auth"[\s]*:[\s]*"([A-Za-z0-9+/=]{20,})"/g,
        redact: '"auth": "[DOCKER_AUTH_REDACTED]"',
        category: "cloud"
    },

    // Kubernetes (cloud)
    {
        name: "Kubernetes Secret Data",
        regex: /data:[\s\S]*?([A-Za-z0-9+/=]{40,})/g,
        redact: "[K8S_SECRET_REDACTED]",
        category: "cloud"
    },

    // Facebook (apiKeys)
    {
        name: "Facebook Access Token",
        regex: /EAA[A-Za-z0-9]{100,}/g,
        redact: "[FACEBOOK_ACCESS_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Twitter (apiKeys)
    {
        name: "Twitter Bearer Token",
        regex: /AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+/g,
        redact: "[TWITTER_BEARER_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Anthropic (ai_ml) — from GitLeaks
    {
        name: "Anthropic API Key",
        regex: /sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{86,}/g,
        redact: "[ANTHROPIC_API_KEY_REDACTED]",
        category: "ai_ml"
    },

    // OpenAI (ai_ml) — improved per GitLeaks (covers sk-proj-, sk-svcacct-, sk-admin-)
    {
        name: "OpenAI API Key (Project/Service/Admin)",
        regex: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{48,180}/g,
        redact: "[OPENAI_API_KEY_REDACTED]",
        category: "ai_ml"
    },
    {
        name: "OpenAI API Key (Legacy)",
        regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
        redact: "[OPENAI_API_KEY_REDACTED]",
        category: "ai_ml"
    },

    // HuggingFace (ai_ml) — from GitLeaks
    {
        name: "HuggingFace Access Token",
        regex: /hf_[a-zA-Z]{34}/g,
        redact: "[HUGGINGFACE_TOKEN_REDACTED]",
        category: "ai_ml"
    },
    {
        name: "HuggingFace Organization API Token",
        regex: /api_org_[a-zA-Z]{34}/gi,
        redact: "[HUGGINGFACE_ORG_TOKEN_REDACTED]",
        category: "ai_ml"
    },

    // Replicate (ai_ml)
    {
        name: "Replicate API Token",
        regex: /r8_[A-Za-z0-9]{38}/g,
        redact: "[REPLICATE_API_TOKEN_REDACTED]",
        category: "ai_ml"
    },

    // Perplexity (ai_ml) — from GitLeaks
    {
        name: "Perplexity API Key",
        regex: /pplx-[a-zA-Z0-9]{48}/g,
        redact: "[PERPLEXITY_API_KEY_REDACTED]",
        category: "ai_ml"
    },

    // Datadog (apiKeys) — improved per GitLeaks
    {
        name: "Datadog API Key",
        regex: /(?:datadog|dd)(?:[_\-\s]*(?:api)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([a-f0-9]{32,40})['"]?/gi,
        redact: "[DATADOG_API_KEY_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Datadog Access Token",
        regex: /(?:datadog)(?:[_\-\s]*(?:access)?[_\-\s]*(?:token|key))[\s]*[=:][\s]*['"]?([a-z0-9]{40})['"]?/gi,
        redact: "[DATADOG_ACCESS_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Datadog App Key",
        regex: /(?:datadog|dd)(?:[_\-\s]*(?:app(?:lication)?)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([a-f0-9]{40})['"]?/gi,
        redact: "[DATADOG_APP_KEY_REDACTED]",
        category: "apiKeys"
    },

    // New Relic (apiKeys)
    {
        name: "New Relic License Key",
        regex: /(?:new[_\-]?relic)(?:[_\-\s]*(?:license)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([A-Za-z0-9]{40})['"]?/gi,
        redact: "[NEWRELIC_LICENSE_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Sentry (apiKeys)
    {
        name: "Sentry DSN",
        regex: /https:\/\/[a-f0-9]{32}@[^\s"']+\.ingest\.sentry\.io\/[0-9]+/g,
        redact: "[SENTRY_DSN_REDACTED]",
        category: "apiKeys"
    },

    // Firebase (apiKeys)
    {
        name: "Firebase Server Key",
        regex: /AAAA[A-Za-z0-9_-]{140,}/g,
        redact: "[FIREBASE_SERVER_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Algolia (apiKeys)
    {
        name: "Algolia Admin API Key",
        regex: /(?:algolia)(?:[_\-\s]*(?:admin|api)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([a-f0-9]{32})['"]?/gi,
        redact: "[ALGOLIA_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Cloudflare (apiKeys)
    {
        name: "Cloudflare API Token",
        regex: /(?:cloudflare|cf)(?:[_\-\s]*(?:api)?[_\-\s]*token)[\s]*[=:][\s]*['"]?([A-Za-z0-9_-]{40})['"]?/gi,
        redact: "[CLOUDFLARE_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Cloudflare Global API Key",
        regex: /(?:cloudflare|cf)(?:[_\-\s]*(?:global)?[_\-\s]*(?:api)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([a-f0-9]{37})['"]?/gi,
        redact: "[CLOUDFLARE_GLOBAL_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // DigitalOcean (apiKeys)
    {
        name: "DigitalOcean Access Token",
        regex: /dop_v1_[a-f0-9]{64}/g,
        redact: "[DIGITALOCEAN_ACCESS_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "DigitalOcean OAuth Token",
        regex: /doo_v1_[a-f0-9]{64}/g,
        redact: "[DIGITALOCEAN_OAUTH_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "DigitalOcean Refresh Token",
        regex: /dor_v1_[a-f0-9]{64}/g,
        redact: "[DIGITALOCEAN_REFRESH_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Vault (apiKeys) — expanded per GitLeaks
    {
        name: "HashiCorp Vault Service Token",
        regex: /hvs\.[A-Za-z0-9_-]{24,}/g,
        redact: "[VAULT_SERVICE_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "HashiCorp Vault Batch Token",
        regex: /hvb\.[A-Za-z0-9_-]{138,300}/g,
        redact: "[VAULT_BATCH_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "HashiCorp Terraform API Token",
        regex: /[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}/gi,
        redact: "[TERRAFORM_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Linear (apiKeys)
    {
        name: "Linear API Key",
        regex: /lin_api_[A-Za-z0-9]{40}/gi,
        redact: "[LINEAR_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Notion (apiKeys) — updated per GitLeaks
    {
        name: "Notion Integration Token (Legacy)",
        regex: /secret_[A-Za-z0-9]{43}/g,
        redact: "[NOTION_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Notion API Token",
        regex: /ntn_[0-9]{11}[A-Za-z0-9]{35}/g,
        redact: "[NOTION_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Supabase (apiKeys)
    {
        name: "Supabase Service Key",
        regex: /sbp_[a-f0-9]{40}/g,
        redact: "[SUPABASE_SERVICE_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Vercel (apiKeys)
    {
        name: "Vercel Token",
        regex: /(?:vercel)(?:[_\-\s]*token)[\s]*[=:][\s]*['"]?([A-Za-z0-9]{24})['"]?/gi,
        redact: "[VERCEL_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Netlify (apiKeys)
    {
        name: "Netlify Access Token",
        regex: /(?:netlify)(?:[_\-\s]*(?:access)?[_\-\s]*token)[\s]*[=:][\s]*['"]?([A-Za-z0-9\-_]{40,})['"]?/gi,
        redact: "[NETLIFY_ACCESS_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Grafana (apiKeys) — from GitLeaks
    {
        name: "Grafana API Key / Token",
        regex: /glc_[A-Za-z0-9+/]{32,400}={0,3}/g,
        redact: "[GRAFANA_API_KEY_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Grafana Service Account Token",
        regex: /glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}/g,
        redact: "[GRAFANA_SA_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // PlanetScale (database) — from GitLeaks
    {
        name: "PlanetScale API Token",
        regex: /pscale_tkn_[A-Za-z0-9=._-]{32,64}/gi,
        redact: "[PLANETSCALE_API_TOKEN_REDACTED]",
        category: "database"
    },
    {
        name: "PlanetScale OAuth Token",
        regex: /pscale_oauth_[A-Za-z0-9=._-]{32,64}/g,
        redact: "[PLANETSCALE_OAUTH_TOKEN_REDACTED]",
        category: "database"
    },
    {
        name: "PlanetScale Password",
        regex: /pscale_pw_[A-Za-z0-9=._-]{32,64}/gi,
        redact: "[PLANETSCALE_PASSWORD_REDACTED]",
        category: "database"
    },

    // Postman (apiKeys) — from GitLeaks
    {
        name: "Postman API Token",
        regex: /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/gi,
        redact: "[POSTMAN_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Prefect (apiKeys) — from GitLeaks
    {
        name: "Prefect API Token",
        regex: /pnu_[a-zA-Z0-9]{36}/g,
        redact: "[PREFECT_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Pulumi (apiKeys) — from GitLeaks
    {
        name: "Pulumi API Token",
        regex: /pul-[a-f0-9]{40}/g,
        redact: "[PULUMI_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Rubygems (apiKeys) — from GitLeaks
    {
        name: "Rubygems API Token",
        regex: /rubygems_[a-f0-9]{48}/g,
        redact: "[RUBYGEMS_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Brevo / Sendinblue (apiKeys) — from GitLeaks
    {
        name: "Brevo / Sendinblue API Token",
        regex: /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}/g,
        redact: "[BREVO_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Mailgun (apiKeys) — from GitLeaks
    {
        name: "Mailgun Private API Token",
        regex: /key-[a-f0-9]{32}/g,
        redact: "[MAILGUN_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },
    {
        name: "Mailgun Public Validation Key",
        regex: /pubkey-[a-f0-9]{32}/g,
        redact: "[MAILGUN_PUB_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Shippo (apiKeys) — from GitLeaks
    {
        name: "Shippo API Token",
        regex: /shippo_(?:live|test)_[a-fA-F0-9]{40}/g,
        redact: "[SHIPPO_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Snyk (apiKeys) — from GitLeaks
    {
        name: "Snyk API Token",
        regex: /(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))[\s]*[=:][\s]*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi,
        redact: "[SNYK_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Doppler (apiKeys) — from TruffleHog
    {
        name: "Doppler API Token",
        regex: /dp\.(?:ct|pt|st|sa|scim|audit)\.[A-Za-z0-9]{40,44}/g,
        redact: "[DOPPLER_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Infracost (apiKeys) — from GitLeaks
    {
        name: "Infracost API Token",
        regex: /ico-[a-zA-Z0-9]{32}/g,
        redact: "[INFRACOST_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Confluent (apiKeys) — from TruffleHog
    {
        name: "Confluent Secret Key",
        regex: /(?:confluent)(?:[_\-\s]*(?:secret)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([A-Za-z0-9/+=]{64})['"]?/gi,
        redact: "[CONFLUENT_SECRET_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Databricks (apiKeys)
    {
        name: "Databricks API Token",
        regex: /dapi[a-f0-9]{32}/g,
        redact: "[DATABRICKS_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Figma (apiKeys)
    {
        name: "Figma Personal Access Token",
        regex: /figd_[A-Za-z0-9_-]{40,}/g,
        redact: "[FIGMA_PAT_REDACTED]",
        category: "apiKeys"
    },

    // Airtable (apiKeys)
    {
        name: "Airtable API Key",
        regex: /(?:airtable)(?:[_\-\s]*(?:api)?[_\-\s]*key)[\s]*[=:][\s]*['"]?([A-Za-z0-9]{14,17})['"]?/gi,
        redact: "[AIRTABLE_API_KEY_REDACTED]",
        category: "apiKeys"
    },

    // Contentful (apiKeys)
    {
        name: "Contentful Delivery API Token",
        regex: /(?:contentful)(?:[_\-\s]*(?:delivery|preview|management)?[_\-\s]*(?:api)?[_\-\s]*(?:token|key))[\s]*[=:][\s]*['"]?([A-Za-z0-9\-_]{43,64})['"]?/gi,
        redact: "[CONTENTFUL_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Okta (apiKeys) — from GitLeaks
    {
        name: "Okta Access Token",
        regex: /(?:okta|OKTA)(?:[_\-\s]*(?:api)?[_\-\s]*(?:token|key|secret))[\s]*[=:][\s]*['"]?(00[A-Za-z0-9=_-]{40,})['"]?/g,
        redact: "[OKTA_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Auth0 (apiKeys)
    {
        name: "Auth0 Management API Token",
        regex: /(?:auth0)(?:[_\-\s]*(?:management|api)?[_\-\s]*(?:token|secret|key))[\s]*[=:][\s]*['"]?([A-Za-z0-9\-_]{30,})['"]?/gi,
        redact: "[AUTH0_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Mapbox (apiKeys) — from GitLeaks
    {
        name: "Mapbox API Token",
        regex: /pk\.[a-z0-9]{60}\.[a-z0-9]{22}/g,
        redact: "[MAPBOX_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Twitch (apiKeys) — from GitLeaks
    {
        name: "Twitch API Token",
        regex: /(?:twitch)(?:[_\-\s]*(?:api)?[_\-\s]*(?:token|key|secret))[\s]*[=:][\s]*['"]?([a-z0-9]{30})['"]?/gi,
        redact: "[TWITCH_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // Readme (apiKeys) — from GitLeaks
    {
        name: "Readme API Token",
        regex: /rdme_[a-z0-9]{70}/g,
        redact: "[README_API_TOKEN_REDACTED]",
        category: "apiKeys"
    },

    // CircleCI (ci_cd) — from GitLeaks
    {
        name: "CircleCI Personal API Token",
        regex: /(?:circle)(?:[_\-\s]*(?:ci)?[_\-\s]*(?:token|key))[\s]*[=:][\s]*['"]?([a-f0-9]{40})['"]?/gi,
        redact: "[CIRCLECI_TOKEN_REDACTED]",
        category: "ci_cd"
    },

    // Drone CI (ci_cd)
    {
        name: "Drone CI Token",
        regex: /(?:drone)(?:[_\-\s]*(?:token|key|secret))[\s]*[=:][\s]*['"]?([A-Za-z0-9]{32,})['"]?/gi,
        redact: "[DRONE_CI_TOKEN_REDACTED]",
        category: "ci_cd"
    },

    // Travis CI (ci_cd) — from GitLeaks
    {
        name: "Travis CI Token",
        regex: /(?:travis)(?:[_\-\s]*(?:ci)?[_\-\s]*(?:token|key))[\s]*[=:][\s]*['"]?([a-z0-9]{22})['"]?/gi,
        redact: "[TRAVISCI_TOKEN_REDACTED]",
        category: "ci_cd"
    },

    // Azure DevOps (ci_cd)
    {
        name: "Azure DevOps PAT",
        regex: /(?:azure[_\-\s]*devops|ado|vsts)(?:[_\-\s]*(?:pat|token|key))[\s]*[=:][\s]*['"]?([A-Za-z0-9]{52,})['"]?/gi,
        redact: "[AZURE_DEVOPS_PAT_REDACTED]",
        category: "ci_cd"
    },

    // Scalingo (ci_cd) — from GitLeaks
    {
        name: "Scalingo API Token",
        regex: /tk-us-[A-Za-z0-9_-]{48}/g,
        redact: "[SCALINGO_API_TOKEN_REDACTED]",
        category: "ci_cd"
    },

    // Base64 encoded secrets (generic)
    {
        name: "Base64 Encoded Secret",
        regex: /(?:secret|password|key|token)[\s]*[=:][\s]*['"]?((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))['"]?/gi,
        redact: '"[BASE64_SECRET_REDACTED]"',
        category: "generic"
    }
];

// Entropy detection utilities
const EntropyDetector = {
    // Shannon entropy calculation
    calculateEntropy(str) {
        const freq = {};
        for (const char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        const len = str.length;
        for (const char in freq) {
            const p = freq[char] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    },

    // Check if string looks like a high-entropy secret
    isHighEntropy(str) {
        // Minimum length for entropy detection
        if (str.length < 16 || str.length > 200) return false;

        // Skip if it's a common word or path
        if (/^[a-z]+$/i.test(str)) return false;
        if (str.includes('/') && str.split('/').length > 2) return false;

        const entropy = this.calculateEntropy(str);

        // Different thresholds for different character sets
        const hasUpper = /[A-Z]/.test(str);
        const hasLower = /[a-z]/.test(str);
        const hasDigit = /[0-9]/.test(str);
        const hasSpecial = /[^A-Za-z0-9]/.test(str);

        const charSetSize = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        // Require higher entropy for more diverse character sets
        const threshold = charSetSize >= 3 ? 4.0 : 4.5;

        return entropy >= threshold;
    },

    // Find high-entropy strings in content
    findHighEntropyStrings(content) {
        const findings = [];

        // Match quoted strings and assignments
        const patterns = [
            /['"]([A-Za-z0-9+/=_\-]{16,})['"]?/g,
            /[=:]\s*['"]?([A-Za-z0-9+/=_\-]{20,})['"]?/g
        ];

        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const candidate = match[1] || match[0];
                if (this.isHighEntropy(candidate)) {
                    findings.push({
                        match: match[0],
                        value: candidate,
                        index: match.index,
                        entropy: this.calculateEntropy(candidate).toFixed(2)
                    });
                }
            }
        }

        // Deduplicate by position
        const seen = new Set();
        return findings.filter(f => {
            const key = `${f.index}-${f.value}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }
};

// File extensions to scan (text-based files)
const SCANNABLE_EXTENSIONS = [
    // Code
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.py', '.pyw', '.pyx',
    '.java', '.kt', '.kts', '.scala',
    '.go', '.rs', '.rb', '.php',
    '.c', '.cpp', '.cc', '.h', '.hpp',
    '.cs', '.fs', '.vb',
    '.swift', '.m', '.mm',
    '.r', '.R', '.jl',
    '.pl', '.pm', '.lua',
    '.sh', '.bash', '.zsh', '.fish',
    '.ps1', '.psm1', '.bat', '.cmd',
    '.sql', '.graphql', '.gql',

    // Config
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
    '.xml', '.plist', '.properties',
    '.env', '.env.local', '.env.development', '.env.production', '.env.test',
    '.conf', '.config', '.settings',

    // Web
    '.html', '.htm', '.css', '.scss', '.sass', '.less',
    '.vue', '.svelte', '.astro',

    // Documentation
    '.md', '.mdx', '.txt', '.rst',

    // Infrastructure
    '.tf', '.tfvars', '.hcl',
    '.dockerfile', '.docker-compose.yml',
    '.k8s.yaml', '.helm',

    // Other
    '.gradle', '.pom', '.sbt',
    '.gemspec', '.podspec',
    '.cabal', '.mix.exs'
];

// Files to always scan regardless of extension
const SCANNABLE_FILENAMES = [
    'Dockerfile', 'Makefile', 'Rakefile', 'Gemfile',
    '.gitconfig', '.npmrc', '.pypirc', '.netrc',
    'credentials', 'secrets', 'config',
    '.htpasswd', '.htaccess',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'
];

// Files/directories to skip
const SKIP_PATTERNS = [
    /node_modules\//,
    /\.git\//,
    /vendor\//,
    /dist\//,
    /build\//,
    /\.next\//,
    /\.nuxt\//,
    /__pycache__\//,
    /\.pytest_cache\//,
    /\.venv\//,
    /venv\//,
    /\.env\//,
    /target\//,
    /\.idea\//,
    /\.vscode\//,
    /coverage\//,
    /\.nyc_output\//
];
