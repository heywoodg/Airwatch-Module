$naPath = 'C:\Git\Airwatch-Module'
set-location $naPath

import-module Pester

Invoke-Pester "$napath\Airwatch.Module.Ver01.Tests.ps1"

