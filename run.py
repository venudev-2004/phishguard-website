import sys
import os
import subprocess

def run():
    """
    Main entry point for running the SafePhishi application on Windows.
    This script handles environment setup and ensures the server starts correctly.
    """
    print("="*60)
    print(" SafePhishi: Starting Local Development Server")
    print("="*60)

    # 1. Check Python version
    print(f"[*] Python Version: {sys.version.split()[0]}")

    # 2. Set environment variables
    # We set these here so they are available to the Flask app
    os.environ['FLASK_APP'] = 'app.py'
    os.environ['FLASK_DEBUG'] = '1'
    os.environ['FLASK_RUN_PORT'] = os.getenv('FLASK_RUN_PORT', '5000')
    os.environ['FLASK_RUN_HOST'] = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    
    # 3. Verify dependencies
    try:
        import flask
        import flask_sqlalchemy
        print("[+] Flask and extensions found.")
    except ImportError as e:
        print(f"[!] Missing dependency: {str(e)}")
        print("[!] Please run: pip install -r requirements.txt")
        return

    # 4. Port Check
    port = os.environ['FLASK_RUN_PORT']
    print(f"[*] Checking if port {port} is available...")
    
    # Simple check using netstat
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        if f":{port}" in result.stdout:
            print(f"[!] Port {port} appears to be in use.")
            print(f"[!] You can change the port by setting FLASK_RUN_PORT environment variable.")
            print(f"    Example: set FLASK_RUN_PORT=5001 && python run.py")
        else:
            print(f"[+] Port {port} is free.")
    except Exception:
        pass # If netstat fails, we'll let Flask try to bind anyway

    # 5. Start the application
    print(f"\n[*] Launching http://{os.environ['FLASK_RUN_HOST']}:{port}/")
    print("[*] Press Ctrl+C to stop the server.\n")

    try:
        # We run 'python app.py' directly because our app.py has a robust __main__ block
        subprocess.run(['python', 'app.py'], check=True)
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")

if __name__ == "__main__":
    run()
