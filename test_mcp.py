import asyncio
import json
from mcp_server import mcp

def extract_tool_result(res):
    """Normalize output whether FastMCP returns strings, dicts, or Content objects."""
    if isinstance(res, tuple):
        res = res[0]
    if isinstance(res, list) and len(res) > 0:
        first = res[0]
        if hasattr(first, "text"):
            return first.text
        return first
    return res

async def test():
    # 1. List all exposed tools
    tools = await mcp.list_tools()
    print("✅ Registered MCP Tools:")
    for t in tools:
        print(f"  - {t.name}: {t.description.strip().splitlines()[0]}")

    # 2. Test Catalog Search
    print("\n--- Testing Tool: search_catalog ---")
    res = await mcp.call_tool("search_catalog", {"query": "boAt earphones", "top_k": 2})
    print(extract_tool_result(res))

    # 3. Test Signed Mandate Generation
    print("\n--- Testing Tool: issue_signed_mandate ---")
    mandate_raw = await mcp.call_tool(
        "issue_signed_mandate", 
        {"user_prompt": "Buy boAt bassheads 100 earphones under 1000 rupees"}
    )
    mandate_str = extract_tool_result(mandate_raw)
    print(mandate_str)
    
    mandate_json = json.loads(mandate_str) if isinstance(mandate_str, str) else mandate_str

    # 4. Test 2PC Execution via MCP Tool
    if mandate_json.get("status") == "APPROVED":
        print("\n--- Testing Tool: execute_two_phase_commit ---")
        exec_res = await mcp.call_tool(
            "execute_two_phase_commit",
            {
                "user_prompt": "Buy boAt bassheads 100 earphones under 1000 rupees",
                "user_id": "agent_mcp_user",
                "mandate": mandate_json["mandate"],
                "cart": mandate_json["cart"],
                "signature": mandate_json["signature"],
                "auto_execute": True
            }
        )
        print(extract_tool_result(exec_res))

    # 5. Inspect Audit Ledger
    print("\n--- Testing Tool: inspect_audit_ledger ---")
    ledger_res = await mcp.call_tool("inspect_audit_ledger", {})
    print(extract_tool_result(ledger_res))

if __name__ == "__main__":
    asyncio.run(test())