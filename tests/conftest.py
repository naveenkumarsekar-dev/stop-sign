import os
import tempfile

os.environ["STOPSIGN_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["STOPSIGN_ADMIN_TOKEN"] = "test-token"
os.environ["STOPSIGN_MODE"] = "combined"
