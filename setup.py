# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'minion.plugin_service'
]

setup(name="minion.arachni_plugin",
      version="0.1",
      description="Arachni Plugin for Minion",
      url="https://github.com/pbkracker/minion-arachni-plugin/",
      author="Patrick Kelley",
      author_email="patrick.kelley@hackerdojo.com",
      packages=['minion', 'minion.plugins'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires)
