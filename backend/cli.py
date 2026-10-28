import argparse

from sqlalchemy import select

from backend.infrastructure.database import SessionLocal
from backend.infrastructure.models import UserModel


def main() -> None:
    parser = argparse.ArgumentParser(description="Yellow Store maintenance commands")
    commands = parser.add_subparsers(dest="command", required=True)
    promote = commands.add_parser("make-admin", help="Promote an existing account to administrator")
    promote.add_argument("email")
    args = parser.parse_args()

    with SessionLocal.begin() as session:
        user = session.scalar(select(UserModel).where(UserModel.email == args.email.strip().lower()))
        if user is None:
            parser.error("No account exists for that email address")
        user.role = "admin"
    print(f"Administrator access enabled for {args.email.strip().lower()}")


if __name__ == "__main__":
    main()
