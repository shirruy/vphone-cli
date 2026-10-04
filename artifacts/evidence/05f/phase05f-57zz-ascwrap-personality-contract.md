# 57ZZ — AppleASCWrapV6 Personality Contract & Provider Matching

## P1: Personality contract (parsed from BootKC prelink plist)

```
P1_PERSONALITY_PARSE: PASS
```

### AppleASCWrapV6

- `IOClass`: `AppleASCWrapV6`
- `IOProviderClass`: `AppleARMIODevice`
- `IONameMatch`: `['iop,ascwrap-v6', 'iop,ascwrap-v7']`
- other keys: CFBundleIdentifier, IOPersonalityPublisher

### AppleASCWrapV6SEP

- `IOClass`: `AppleASCWrapV6SEP`
- `IOProviderClass`: `AppleARMIODevice`
- `IONameMatch`: `['iop-sep,ascwrap-v6', 'iop-sep,ascwrap-v7']`
- other keys: CFBundleIdentifier, IOPersonalityPublisher

### AppleASCWrapV6SISP

- `IOClass`: `AppleASCWrapV6SISP`
- `IOProviderClass`: `AppleARMIODevice`
- `IONameMatch`: `['iop-isp,ascwrap-v6']`
- other keys: CFBundleIdentifier, IOPersonalityPublisher

## P2: DeviceTree topology around arm-io/ans

### control

#### `/arm-io/ans`
- compatible: `[]`
- device_type: `['ans']`
- role: `['ANS2']`
- iop-version: `0x1`
- reg: 0x77400000+0x6c000, 0x77050000+0x4000, 0x0+0x0, 0x7bcc0000+0x60000, 0x79000000+0x1000000, 0x7bb90000+0xc000, 0x7bd47c00+0x4000, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x7b100000+0x44000
- children: ['iop-ans-nub']

#### `/arm-io/ans/iop-ans-nub`
- compatible: `[]`
- device_type: `[]`
- children: []

### ans58a

#### `/arm-io/ans`
- compatible: `[]`
- device_type: `['ans']`
- role: `['ANS2']`
- iop-version: `0x1`
- reg: 0x77400000+0x6c000, 0x77050000+0x4000, 0x0+0x0, 0x7bcc0000+0x60000, 0x79000000+0x1000000, 0x7bb90000+0xc000, 0x7bd47c00+0x4000, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x0+0x0, 0x7b100000+0x44000
- children: ['iop-ans-nub']

#### `/arm-io/ans/iop-ans-nub`
- compatible: `['iop-nub,rtbuddy-v2']`
- device_type: `[]`
- children: []

## P3: Personality-to-DT match matrix

Matched rows only (name-match satisfied):

_No personality name-match against any ANS-related node in either fixture._

## P4: H1 classification

```
H1_MISSING_ASCWRAP_PROVIDER_IDENTITY: SUPPORTED
```
