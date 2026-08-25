import argparse
import sys
import unittest
from unittest.mock import Mock, patch

from scripts import start_demo


class StartDemoTests(unittest.TestCase):
    def test_port_validator_accepts_valid_port(self) -> None:
        self.assertEqual(start_demo._port("18002"), 18002)

    def test_port_validator_rejects_out_of_range_port(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            start_demo._port("70000")

    def test_main_refuses_an_occupied_port_before_spawning_services(self) -> None:
        with (
            patch.object(start_demo, "run_checks", return_value=[]),
            patch.object(start_demo, "_port_available", side_effect=[False, True]),
            patch.object(start_demo.subprocess, "Popen") as popen,
            patch.object(sys, "argv", ["start_demo.py"]),
        ):
            self.assertEqual(start_demo.main(), 1)

        popen.assert_not_called()

    def test_main_passes_api_port_to_ui_environment(self) -> None:
        api_process = Mock()
        api_process.wait.return_value = 0
        ui_process = Mock()
        with (
            patch.object(start_demo, "run_checks", return_value=[]),
            patch.object(start_demo, "_port_available", return_value=True),
            patch.object(
                start_demo.subprocess,
                "Popen",
                side_effect=[api_process, ui_process],
            ) as popen,
            patch.object(
                sys,
                "argv",
                ["start_demo.py", "--api-port", "18002", "--ui-port", "18502"],
            ),
        ):
            self.assertEqual(start_demo.main(), 0)

        ui_kwargs = popen.call_args_list[1].kwargs
        self.assertEqual(ui_kwargs["env"]["QR_API_BASE_URL"], "http://127.0.0.1:18002")
        self.assertIn("18002", popen.call_args_list[0].args[0])
        self.assertIn("18502", popen.call_args_list[1].args[0])
        ui_process.terminate.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
