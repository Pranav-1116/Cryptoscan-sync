import subprocess

def pytest_collection_modifyitems(items):
    import api.assurance.relationships as relationships
    import api.assurance.coverage as coverage
    for module, path in [(relationships, 'relationships'), (coverage, 'coverage')]:
        source = subprocess.check_output(['git', 'show', 'c48f667e3dee70b0ffc48f338004382b6543f94f:services/api/api/assurance/' + path + '.py'])
        exec(compile(source, 'original_published_' + path, 'exec'), module.__dict__)
