# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import os
import sys

from PyInstaller.building.api import PYZ, EXE
from PyInstaller.building.build_main import Analysis
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# Volatility must be findable in sys.path in order for collect_submodules to work
# This adds the current working directory, which should usually do the trick
sys.path.append(os.getcwd())

if not os.path.exists('resources/node_modules'):
    print("Please run 'npm install' before attempting to build an executable")
    sys.exit(1)

a = Analysis(['vol.py'],
             pathex = [],
             binaries = [],
             datas = [('resources', 'resources')] + \
                     collect_data_files('volumetric') + \
                     collect_data_files('volatility.framework') + \
                     collect_data_files('volatility.framework.automagic', include_py_files = True) + \
                     collect_data_files('volatility.framework.plugins', include_py_files = True) + \
                     collect_data_files('volatility.schemas') + \
                     collect_data_files('volatility.plugins', include_py_files = True),
             hiddenimports = collect_submodules('volatility.framework.automagic') + \
                             collect_submodules('volatility.framework.plugins') + \
                             collect_submodules('volatility.framework.symbols'),
             hookspath = [],
             runtime_hooks = [],
             excludes = [],
             win_no_prefer_redirects = False,
             win_private_assemblies = False,
             cipher = block_cipher,
             noarchive = False)
pyz = PYZ(a.pure, a.zipped_data,
          cipher = block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name = 'volumetric',
          debug = False,
          bootloader_ignore_signals = False,
          strip = False,
          upx = True,
          runtime_tmpdir = None,
          console = True)
