Minion Arachni Plugin
===================

This is a plugin for Minion that executes the Arachni tool. It assumes Arachni is installed on your system and that is is on the system PATH.  The arachni_rpcd process must be running. It currently relies on the experimental branch of Arachni.

Forked from the current Arachni plugin : https://github.com/pbkracker/minion-arachni-plugin

Installation
------------

It assumes that you have already Minion installed (https://github.com/mozilla/minion)

First, you need to have Arachni installed on your server or local machine.

To install Arachni:

```gem install arachni # Use sudo if you get permission errors.```

Secondly, you need to have Arachni-RPC pure installed on the same machine as Minion.

To install Arachni-RPC pure:

```gem install arachni-rpc-pure # Use sudo if you get permission errors.```

Then, install the plugin by running the following command in the minion-arachni-plugin repository:

```python setup.py install```

Example of plan
---------------

```
[
  {
    "configuration": {
      "audit_links": "",
      "audit_cookies": "",
      "modules": "xss*",
      "audit_forms": ""
    },
    "description": "",
    "plugin_name": "minion.plugins.arachni.ArachniPlugin"
  }
]
```
