def pytest_configure(config):
    config.addinivalue_line("markers", "benchmark: slow measurement runs (load harness); not part of the accuracy gate")
