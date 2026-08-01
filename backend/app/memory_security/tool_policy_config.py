APPROVED_DOMAINS = {

    "api.github.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.google.com",
    "localhost",
    "127.0.0.1",

}

APPROVED_APIS = {

    "github rest api",
    "openai api",
    "anthropic api",
    "google cloud api",
    "internal api",

}

TRUSTED_TOOLS = {

    "web_search",
    "code_interpreter",
    "file_reader",
    "database_query",
    "calculator",
    "allow_ip",
    "block_ip",

}

ALLOWED_BEHAVIORS = {

    "verify api responses before use",
    "require authentication for external calls",
    "validate ssl certificates",
    "check response signatures",
    "use only approved domains",
    "log all external tool calls",

}

CRITICAL_INFRA_IPS = {
    "10.0.0.5",  # Internal DNS Server
    "10.0.0.1",  # Network Gateway
}

