
from app.agent.agent_loop import MoriartyAgentLoop


agent = MoriartyAgentLoop(max_tests=3)

result = agent.run()

print("\n========== FINAL REPORT ==========")
print("Tests executed:", len(result.tests_executed))
print("Evidence collected:", len(result.evidence))
print("Final action:", result.final_action)
print("Final reason:", result.final_reason)
