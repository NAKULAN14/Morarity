from app.agent.agent_loop import MoriartyAgentLoop


def main():
    agent = MoriartyAgentLoop(max_tests=3)
    result = agent.run()

    print("\n========== FINAL REPORT ==========")
    print(f"Tests executed: {len(result.tests_executed)}")
    print(f"Evidence collected: {len(result.evidence)}")
    print(f"Final action: {result.final_action}")
    print(f"Final reason: {result.final_reason}")
    print(f"Verdict: {result.verdict.value}")
    print(f"Verdict summary: {result.verdict_summary}")


if __name__ == "__main__":
    main()