import argparse
import itertools

import paramiko

USERNAMES = ["root", "admin", "user", "test", "oracle", "postgres"]
PASSWORDS = ["123456", "password", "admin", "toor", "qwerty", "letmein"]


def try_login(host: str, port: int, username: str, password: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       look_for_keys=False, allow_agent=False, timeout=5,
                       banner_timeout=5, auth_timeout=5)
        return "ACCEPTED (unexpected!)"
    except paramiko.AuthenticationException:
        return "rejected"
    except Exception as exc:
        return f"error: {exc}"
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="honeypot")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--usernames", help="comma-separated list to try instead of the defaults")
    args = parser.parse_args()

    usernames = args.usernames.split(",") if args.usernames else USERNAMES
    creds = itertools.cycle(zip(usernames, itertools.cycle(PASSWORDS)))
    for i, (user, pwd) in enumerate(itertools.islice(creds, args.attempts), 1):
        print(f"[{i}/{args.attempts}] {user}:{pwd} -> {try_login(args.host, args.port, user, pwd)}")


if __name__ == "__main__":
    main()
