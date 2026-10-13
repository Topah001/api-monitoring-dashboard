import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import app

PUBLIC=['93.184.216.34']
def public_info(*args,**kwargs): return [(None,None,None,None,(PUBLIC[0],0))]
class MonitorTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.db=Path(self.temp.name)/'monitor.db'; app.initialize(self.db)
 def tearDown(self): self.temp.cleanup()
 def test_only_explicit_http_public_urls(self):
  with patch.object(app.socket,'getaddrinfo',side_effect=public_info):
   self.assertEqual(app.validate_url('https://api.example.org/health')['host'],'api.example.org')
   for url in ('file:///etc/passwd','ftp://example.org','http://localhost','http://user:pass@example.org','http://example.org/#frag','http://example.org:99999'):
    with self.subTest(url=url), self.assertRaises(ValueError): app.validate_url(url)
 def test_private_and_mixed_dns_answers_are_blocked(self):
  with patch.object(app.socket,'getaddrinfo',return_value=[(None,None,None,None,('10.0.0.5',80))]), self.assertRaises(ValueError): app.validate_url('http://api.example.org')
  with patch.object(app.socket,'getaddrinfo',return_value=[(None,None,None,None,('93.184.216.34',80)),(None,None,None,None,('169.254.169.254',80))]), self.assertRaises(ValueError): app.validate_url('http://api.example.org')
  with self.assertRaises(ValueError): app.validate_url('http://127.0.0.1')
 def test_check_uses_mock_transport_and_records_history(self):
  with patch.object(app.socket,'getaddrinfo',side_effect=public_info):
   item=app.create_check({'url':'https://api.example.org/health','timeout':2,'interval_seconds':10},self.db)
   transport=lambda target,timeout: 204
   result=app.run_check(item['id'],self.db,transport)
   self.assertEqual(result['status_code'],204); self.assertTrue(result['ok'])
   history=app.get_history(item['id'],self.db)
   self.assertEqual(len(history),1); self.assertEqual(history[0]['status_code'],204)
 def test_safety_revalidated_before_each_check(self):
  with patch.object(app.socket,'getaddrinfo',side_effect=[public_info(),[(None,None,None,None,('169.254.169.254',80))]]):
   item=app.create_check({'url':'http://api.example.org','timeout':2,'interval_seconds':10},self.db)
   result=app.run_check(item['id'],self.db,lambda *args: 200)
   self.assertFalse(result['ok']); self.assertIn('globally routable',result['error'])
   self.assertEqual(len(app.get_history(item['id'],self.db)),1)
 def test_timeout_and_interval_bounds(self):
  with patch.object(app.socket,'getaddrinfo',side_effect=public_info):
   for timeout,interval in ((31,10),(1,4)):
    with self.assertRaises(ValueError): app.create_check({'url':'http://api.example.org','timeout':timeout,'interval_seconds':interval},self.db)
 def test_transport_failure_is_recorded(self):
  with patch.object(app.socket,'getaddrinfo',side_effect=public_info):
   item=app.create_check({'url':'http://api.example.org','timeout':2,'interval_seconds':10},self.db)
   result=app.run_check(item['id'],self.db,lambda *args: (_ for _ in ()).throw(TimeoutError('timed out')))
   self.assertFalse(result['ok']); self.assertIn('timed out',result['error'])
if __name__=='__main__': unittest.main()
