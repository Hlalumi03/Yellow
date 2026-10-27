from http.server import HTTPServer

from backend.app import AuthHandler, initialize_store


if __name__ == "__main__":
    initialize_store()
    print("Yellow Store running at http://127.0.0.1:8000")
    try:
        HTTPServer(("127.0.0.1", 8000), AuthHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
