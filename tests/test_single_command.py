import unittest

import auto_unlock_cryptnux as tpm2


class SingleCommandWorkflowTests(unittest.TestCase):
    def test_build_single_command_uses_explicit_device(self):
        cmd = tpm2.build_single_tpm2_workflow_command('/dev/sda5')
        self.assertIn('systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+2+4+7 /dev/sda5', cmd)
        self.assertIn("sed -i '/crypto_LUKS\\|luks-/s/none/none tpm2-device=auto/' /etc/crypttab", cmd)
        self.assertIn('dracut -f --regenerate-all', cmd)

    def test_build_single_command_discovers_luks_device_when_none(self):
        cmd = tpm2.build_single_tpm2_workflow_command(None)
        self.assertIn('$(lsblk -lno NAME,FSTYPE | awk', cmd)
        self.assertIn('crypto_LUKS', cmd)


if __name__ == '__main__':
    unittest.main()
