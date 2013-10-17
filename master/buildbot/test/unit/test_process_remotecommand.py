# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members

from twisted.trial import unittest
from buildbot.process import remotecommand


class TestRemoteShellCommand(unittest.TestCase):

    def test_obfuscated_arguments(self):
        command = ["echo",
            ("obfuscated", "real", "fake"),
            "test",
            ("obfuscated", "real2", "fake2"),
            ("not obfuscated", "a", "b"),
            ("obfuscated"),  # not obfuscated
            ("obfuscated", "test"),  # not obfuscated
            ("obfuscated", "1", "2", "3"),  # not obfuscated)
            ]
        cmd = remotecommand.RemoteShellCommand("build", command)
        self.assertEqual(cmd.command, command)
        self.assertEqual(cmd.fake_command, ["echo",
            "fake",
            "test",
            "fake2",
            ("not obfuscated", "a", "b"),
            ("obfuscated"),  # not obfuscated
            ("obfuscated", "test"),  # not obfuscated
            ("obfuscated", "1", "2", "3"),  # not obfuscated)
            ])

        command = "echo test"
        cmd = remotecommand.RemoteShellCommand("build", command)
        self.assertEqual(cmd.command, command)
        self.assertEqual(cmd.fake_command, command)
