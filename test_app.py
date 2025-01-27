import unittest
from App import app, test_database_connection, test_registration, test_login, test_reservation, test_game_availability, \
    test_invalid_registration, test_past_reservation
from datetime import datetime, timedelta


class TestSystemTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()

    def test_all_functionalities(self):
        with app.app_context():
            # Test połączenia z bazą
            self.assertTrue(test_database_connection())

            # Test rejestracji
            self.assertTrue(test_registration())

            # Test logowania
            login_result = test_login()
            self.assertTrue(login_result)  # Zmiana z assertFalse na assertTrue

            # Test rezerwacji
            self.assertTrue(test_reservation())

            # Test dostępności gier
            self.assertTrue(test_game_availability())

    def test_invalid_scenarios(self):
        with app.app_context():
            # Test duplikacji rejestracji
            result = test_invalid_registration()
            self.assertTrue(result)  # Sprawdź czy test przeszedł

            # Test przeszłej rezerwacji
            result = test_past_reservation()
            self.assertTrue(result)  # Sprawdź czy test przeszedł

    def test_web_interface(self):
        # Test GET request
        response = self.app.get('/system_tests')  # Zmiana adresu
        self.assertEqual(response.status_code, 200)

        # Test POST request
        response = self.app.post('/system_tests')  # Zmiana adresu
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()