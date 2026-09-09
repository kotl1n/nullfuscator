# Third-party dependencies

The project code is MIT licensed. Bundled dependencies retain their own licenses.
The executable JAR includes these notices and license texts under `META-INF/`.

| Dependency | Version | License | Source |
| --- | --- | --- | --- |
| ASM (core, analysis, commons, tree, util) | 9.10.1 | BSD-3-Clause | https://asm.ow2.io/ |
| Typesafe Config | 1.4.2 | Apache-2.0 | https://github.com/lightbend/config/tree/v1.4.2 |

ASM: Copyright (c) 2000-2011 INRIA, France Telecom. All rights reserved.
See `licenses/ASM-BSD-3-Clause.txt`.

Typesafe Config: Copyright (C) 2011-2012 Typesafe Inc.
See `licenses/Typesafe-Config-Apache-2.0.txt` and upstream
source attribution. Dependency class bytes are bundled without modification;
packaging removes dependency manifests, module descriptors and signatures.

`libs/SHA256SUMS` records the exact vendored JARs used by the offline build.
