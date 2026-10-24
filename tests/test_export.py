"""
Tests for netwarden.export and the dashboard's download endpoints: the device CSV
(UTF-8 BOM, localized headers, formula-injection safe) and the Markdown report
(localized digest + inventory, hostile text escaped). Ephemeral 127.0.0.1 server.
"""
import csv
import http.client
import io
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import export, i18n, store, web
from test_offline_ai import CAM, PS5, seed  # same little home


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        seed(self.db)
        # hostile user text: a spreadsheet formula and Markdown/HTML table breakers
        store.set_label(self.db, CAM, '=HYPERLINK("http://evil","click")')
        store.set_label(self.db, PS5, "PS5 | <b>living</b> room")

    def rows(self, lang="en"):
        body = export.devices_csv(self.db, lang)
        self.assertTrue(body.startswith("﻿".encode("utf-8")))   # Excel-friendly BOM
        return list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))

    def test_csv_one_row_per_device_with_localized_header(self):
        rows = self.rows("en")
        self.assertEqual(rows[0][0], "Name")
        self.assertEqual(rows[0][-2], "Downloaded (7 d, bytes)")
        self.assertEqual(len(rows) - 1, 3)
        zh = self.rows("zh-Hant")
        self.assertEqual(zh[0][0], "名稱")

    def test_csv_neutralizes_formulas(self):
        rows = self.rows()
        cam = next(r for r in rows[1:] if r[4] == CAM)
        self.assertTrue(cam[0].startswith("'="))      # name (= the label)
        self.assertTrue(cam[1].startswith("'="))      # label column
        self.assertEqual(export.safe_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(export.safe_cell("@SUM(1)"), "'@SUM(1)")
        self.assertEqual(export.safe_cell("-2+3"), "'-2+3")
        self.assertEqual(export.safe_cell(42), 42)
        self.assertEqual(export.safe_cell(None), "")
        self.assertEqual(export.safe_cell("ipcam"), "ipcam")

    def test_csv_content(self):
        rows = self.rows()
        head = rows[0]
        cam = dict(zip(head, next(r for r in rows[1:] if r[4] == CAM)))
        self.assertEqual(cam["Security alerts (7 d)"], "1")      # xmeye.net
        self.assertEqual(cam["Uploaded (7 d, bytes)"], str(9 * 10**8))
        self.assertIn("XMEye", cam["Top services (7 d)"])
        vac = dict(zip(head, next(r for r in rows[1:] if r[0] == "roborock-vacuum")))
        self.assertEqual(vac["Downloaded (7 d, bytes)"], "")     # no traffic -> blank

    def test_report_markdown(self):
        md = export.report_md(self.db, "en")
        self.assertTrue(md.startswith("# " + i18n.t("export.report_title", "en")))
        self.assertIn(i18n.t("digest.title", "en"), md)
        self.assertIn("xmeye.net", md)
        self.assertIn("PS5 \\| &lt;b&gt;living&lt;/b&gt; room", md)   # escaped in the table
        self.assertNotIn("<b>", md.split("## ")[-1])                 # inventory has no raw HTML
        self.assertIn("↑ Uploaded (7 d)", md)
        self.assertNotIn(i18n.t("export.demo_note", "en"), md)
        zh = export.report_md(self.db, "zh-Hant")
        self.assertIn("網路報告", zh)
        self.assertIn("裝置清單", zh)

    def test_report_marks_demo(self):
        store.set_meta(self.db, "demo", "1")
        self.assertIn(i18n.t("export.demo_note", "en"), export.report_md(self.db, "en"))

    def test_fence_cannot_be_closed_by_a_name(self):
        store.set_label(self.db, CAM, "cam```\n# injected")
        md = export.report_md(self.db, "en")
        self.assertEqual(md.count("```"), 2)


class ExportEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = Path(cls.tmp.name) / "t.db"
        db = store.connect(path)
        seed(db)
        db.close()
        cls.srv = web.make_server(path, 0, {}, "en")
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path)
        r = c.getresponse()
        return r, r.read()

    def test_csv_download(self):
        r, body = self.get("/api/export/devices.csv?lang=de")
        self.assertEqual(r.status, 200)
        self.assertIn("text/csv", r.getheader("content-type"))
        self.assertRegex(r.getheader("content-disposition"),
                         r'^attachment; filename="netwarden-devices-\d{8}\.csv"$')
        self.assertTrue(body.decode("utf-8-sig").startswith("Name,Deine Bezeichnung"))

    def test_report_download(self):
        r, body = self.get("/api/export/report.md?lang=fr")
        self.assertEqual(r.status, 200)
        self.assertIn("text/markdown", r.getheader("content-type"))
        self.assertIn("attachment;", r.getheader("content-disposition"))
        self.assertIn("Rapport réseau netwarden", body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
