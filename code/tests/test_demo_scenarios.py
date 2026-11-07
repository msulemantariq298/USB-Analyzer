from usb_analyzer.demo_runner import run_all_five_scenarios


def test_all_five_scenarios_pass_uninterrupted(tmp_path):
    results = run_all_five_scenarios(db_path=tmp_path / "test_demo.db")

    assert len(results) == 5
    for scenario_name, passed in results.items():
        assert passed is True, f"{scenario_name} did not pass!"

