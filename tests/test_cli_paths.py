from src import main


def test_normalize_file_path_expands_home(
    monkeypatch,
    tmp_path
):
    monkeypatch.setenv(
        "HOME",
        str(tmp_path)
    )

    result = main.normalize_file_path(
        "~/CTF/challenge.bin"
    )

    expected = (
        tmp_path
        / "CTF"
        / "challenge.bin"
    )

    assert result == str(expected)


def test_smart_analysis_interactive_expands_home(
    monkeypatch,
    tmp_path
):
    monkeypatch.setenv(
        "HOME",
        str(tmp_path)
    )

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: "~/CTF/challenge.bin"
    )

    captured = {}

    def fake_smart_analyze(file_path):
        captured["file_path"] = file_path

    monkeypatch.setattr(
        main,
        "smart_analyze",
        fake_smart_analyze
    )

    main.run_smart_analysis_interactive()

    expected = (
        tmp_path
        / "CTF"
        / "challenge.bin"
    )

    assert captured["file_path"] == str(expected)
