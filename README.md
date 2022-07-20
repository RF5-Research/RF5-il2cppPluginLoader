# RF5-il2cppPluginLoader
 A plugin and file loader for Rune Factory 5 (RF5) (Windows)
## Installation
Extract contents to directory containing the game executable. Run ``il2cppPluginLoader.exe`` to load plugins and/or mods. Running ``il2cppPluginLoader.exe`` will create the ``mods`` and ``plugins`` directory.  
- ``mods`` is to load game files to patch
  -   ex) ``mods\StreamingAssets\aa\StandaloneWindows64\382aa2501e16ef256258fc102a8fcea5.bundle`` to replace ``Rune Factory 5_Data\StreamingAssets\aa\StandaloneWindows64\382aa2501e16ef256258fc102a8fcea5.bundle``
- ``plugins`` is to load dlls to execute custom code
## Building
### Dependencies
- [polyhook2](https://github.com/stevemk14ebr/PolyHook_2_0)
- [json](https://github.com/nlohmann/json)

Install the aforementioned dependencies with your preferred package manager, preferrably [vcpkg](https://github.com/microsoft/vcpkg), or build manually.
