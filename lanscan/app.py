"""Application entry point."""

import sys
import threading

from gi.repository import Adw, Gio, GLib, Gtk

from . import (
    APP_ID, APP_NAME, AUTHOR, WEBSITE, __version__, scanner, updates)
from .store import Store
from .window import Window


class Application(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.store = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        self.store = Store()
        # Online state is only meaningful after a scan in this session.
        self.store.mark_all_offline()
        for name, callback, accels in (
                ("about", self._about, []),
                ("quit", lambda *a: self.quit(), ["<Control>q"])):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            self.set_accels_for_action(f"app.{name}", accels)

    def do_activate(self):
        window = self.get_active_window()
        if window is None:
            window = Window(self, self.store)
            threading.Thread(
                target=self._update_vendors, daemon=True).start()
        window.present()

    def _update_vendors(self):
        """Fetch the MAC vendor list when it is missing or a month old."""
        try:
            scanner.vendors.update()
        except Exception as e:
            print(f"lanscan: vendor list not updated: {e}", file=sys.stderr)
        GLib.idle_add(self._reidentify)

    def _reidentify(self):
        if self.store.reidentify(scanner.vendors):
            window = self.get_active_window()
            if window is not None:
                window.refresh()

    def _about(self, *_args):
        comments = ("A graphical overview of the devices on your network. "
                    "Scanning is done by nmap.")
        dialog = Adw.AboutDialog(
            application_name=APP_NAME, version=__version__,
            application_icon=APP_ID,
            comments=comments + "\n\nChecking for a new version…",
            developer_name=AUTHOR, website=WEBSITE,
            issue_url=WEBSITE + "/issues", copyright=f"© 2026 {AUTHOR}",
            license_type=Gtk.License.GPL_3_0)
        dialog.present(self.get_active_window())

        def check():
            url = ""
            try:
                latest, page = updates.latest_release()
            except Exception:
                note = "Could not check for a new version."
            else:
                if updates.is_newer(latest, __version__):
                    note, url = f"Version {latest} is available.", page
                else:
                    note = "This is the latest version."
            GLib.idle_add(done, note, url, latest if url else "")

        def done(note, url, latest):
            dialog.set_comments(f"{comments}\n\n{note}")
            if url:
                dialog.add_link(f"Get Version {latest}", url)

        threading.Thread(target=check, daemon=True).start()


def main():
    return Application().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
