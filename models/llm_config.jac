"""Featherless model routing for DepGraph walkers."""

import from byllm.lib { Model }

glob code_llm = Model(
    model_name="featherless/Qwen/Qwen2.5-Coder-32B-Instruct",
    config={
        "api_base": "https://api.featherless.ai/v1",
        "http_client": True
    }
);

glob routing_llm = Model(
    model_name="featherless/deepseek-ai/DeepSeek-V3-0324",
    config={
        "api_base": "https://api.featherless.ai/v1",
        "http_client": True
    }
);
