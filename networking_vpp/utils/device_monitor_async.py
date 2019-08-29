# Copyright (c) 2019 Cisco Systems, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import eventlet.queue
import logging
import time

import networking_vpp.utils.device_monitor as device_monitor


LOG = logging.getLogger(__name__)


class AsyncDeviceMonitor(object):
    """Eventlet-aware async version of device monitor.

    This ensures, in multithreaded apps, that a devmon callback does not end up
    in a deadlock due to the kernel writing additional devmon records in the
    callback.
    """

    def __init__(self, *args, **kwargs):
        self.device_monitor = device_monitor.DeviceMonitor(*args, **kwargs)
        self.device_monitor.on_add(self._recv_add)
        self.device_monitor.on_add(self._recv_del)

        # List of callback functions to be executed on device add/delete events
        self.add_cb = []
        self.del_cb = []

        self.events = eventlet.queue.Queue()

    # These functions imitate DeviceMonitor behaviour.

    def on_add(self, func):
        """Add a function to be called when new i/f is found."""
        self.add_cb.append(func)

    def on_del(self, func):
        """Add a function to be called when i/f goes away."""
        self.del_cb.append(func)

    def _dev_add(self, dev_name):
        """Run all registered add callbacks."""
        for f in self.add_cb:
            f(dev_name)

    def _dev_del(self, dev_name):
        """Run all registered delete callbacks."""
        for f in self.del_cb:
            f(dev_name)

    # These functions deal with making callbacks asynchronous

    def start(self):
        """Run necessary threads."""
        eventlet.spawn_n(self.device_monitor.run)
        eventlet.spawn_n(self._bg_loop)

    def _recv_add(self, dev_name):
        """A real DeviceMonitor calls this when a device is added.

        Takes little to no time to add the event to a list
        """
        self.events.put(('add', dev_name,))

    def _recv_del(self, dev_name):
        """A real DeviceMonitor calls this when a device is deleted.

        Takes little to no time to add the event to a list
        """
        self.events.put(('del', dev_name,))

    def _bg_loop(self):
        while True:
            try:
                # Wait for at least one device event
                ev = self.events.get()

                kind, dev_name = ev

                if kind == 'add':
                    self._dev_add(dev_name)
                else:
                    self._dev_del(dev_name)

            except Exception as e:
                LOG.error('Unexpected exception in async device_monitor: %s',
                          e)
                # Avoid thrashing
                time.sleep(1)
                # Continue with loop
