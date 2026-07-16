import socket

import click
from sqlalchemy import inspect, text

from . import create_app
from .extensions import db
from .models import User
from .migrations import upgrade_database
from .jobs import process_pending_jobs
from .security import USERNAME_RE, require_password_strength


@click.group()
def cli():
    """Manage a DigitalPlat Domain OSS installation."""


@cli.command("init-db")
def init_db():
    app = create_app()
    with app.app_context():
        version = upgrade_database()
    click.secho(f"Database upgraded to schema {version}.", fg="green")
    click.echo("Open /setup in your browser to create the first administrator.")


@cli.command("upgrade")
def upgrade():
    """Apply all pending database migrations."""
    app = create_app()
    with app.app_context():
        version = upgrade_database()
    click.secho(f"Database is at schema {version}.", fg="green")


@cli.command("worker")
@click.option("--once", is_flag=True, help="Process one batch and exit.")
@click.option("--interval", default=5, show_default=True, type=int)
def worker(once, interval):
    """Process pending DNS synchronization jobs."""
    import time

    app = create_app()
    while True:
        with app.app_context():
            completed, found = process_pending_jobs()
            if found:
                click.echo(f"Processed {found} jobs; {completed} completed.")
        if once:
            return
        time.sleep(max(1, interval))


@cli.command("doctor")
def doctor():
    app = create_app()
    failures = 0
    with app.app_context():
        try:
            db.session.execute(text("SELECT 1"))
            click.secho("[ok] Database connection", fg="green")
        except Exception as exc:
            failures += 1
            click.secho(f"[failed] Database connection: {exc}", fg="red")
        if not inspect(db.engine).has_table("user"):
            failures += 1
            click.secho("[action] Run ./panel install to initialize the database", fg="yellow")
        elif User.query.filter_by(is_admin=True).first():
            click.secho("[ok] Administrator account", fg="green")
        else:
            click.secho("[action] Complete the web setup wizard", fg="yellow")
        try:
            socket.getaddrinfo("localhost", 80)
            click.secho("[ok] Local network resolver", fg="green")
        except OSError as exc:
            failures += 1
            click.secho(f"[failed] Local resolver: {exc}", fg="red")
        scheme = app.config["SQLALCHEMY_DATABASE_URI"].split(":", 1)[0]
        click.echo(f"Database driver: {scheme}")
        click.echo(f"Cookie secure mode: {app.config['SESSION_COOKIE_SECURE']}")
    if failures:
        raise SystemExit(1)


@cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--email", prompt=True)
@click.password_option(confirmation_prompt=True)
def create_admin(username, email, password):
    username = username.strip().lower()
    email = email.strip().lower()
    error = require_password_strength(password)
    if not USERNAME_RE.fullmatch(username):
        raise click.ClickException("Invalid username")
    if "@" not in email:
        raise click.ClickException("Invalid email")
    if error:
        raise click.ClickException(error)
    app = create_app()
    with app.app_context():
        if User.query.filter((User.username == username) | (User.email == email)).first():
            raise click.ClickException("Username or email already exists")
        user = User(username=username, email=email, is_admin=True, role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    click.secho("Administrator created.", fg="green")


if __name__ == "__main__":
    cli()
