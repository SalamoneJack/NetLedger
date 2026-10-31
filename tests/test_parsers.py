from __future__ import annotations

import pytest

from netledger.drivers import (
    checkpoint,
    cisco,
    dell,
    extreme,
    fortinet,
    hpe,
    huawei,
    mikrotik,
    paloalto,
    ruckus,
    vyos,
)
from netledger.drivers.parsing import (
    hostname_from_prompt,
    parse_duration,
    parse_kv,
    parse_meminfo,
    parse_size,
    parse_top,
    status_ok,
)

DAY = 86400


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("10 days, 3 hours, 25 minutes", 10 * DAY + 3 * 3600 + 25 * 60),
        ("1 year, 2 weeks, 3 days, 4 hours, 5 minutes", 365 * DAY + 14 * DAY + 3 * DAY + 4 * 3600 + 300),
        ("1w2d3h25m10s", 9 * DAY + 3 * 3600 + 25 * 60 + 10),
        ("10 days, 3:25:01", 10 * DAY + 3 * 3600 + 25 * 60 + 1),
        ("2 days 03:25:10", 2 * DAY + 3 * 3600 + 25 * 60 + 10),
        ("10 days 3 hrs 25 mins 10 secs", 10 * DAY + 3 * 3600 + 25 * 60 + 10),
        ("40 days,  21 hours,  32 minutes", 40 * DAY + 21 * 3600 + 32 * 60),
        ("125 mins", 125 * 60),
        ("no uptime here", None),
        ("", None),
    ],
)
def test_parse_duration(text: str, seconds: float | None) -> None:
    assert parse_duration(text) == seconds


def test_parse_size_and_helpers() -> None:
    assert parse_size("852.4MiB") == int(852.4 * 1024**2)
    assert parse_size("1907272k") == 1907272 * 1024
    assert parse_size("333,447,168") == 333447168
    assert parse_size("4 GB") == 4 * 1024**3
    assert parse_size("512 kbytes") == 512 * 1024
    assert parse_size("lots") is None
    assert status_ok("OK") is True and status_ok("Failed") is False and status_ok("Not Present") is None
    assert hostname_from_prompt("router1#") == "router1"
    assert hostname_from_prompt("<HUAWEI-SW>") == "HUAWEI-SW"
    assert hostname_from_prompt("[admin@MikroTik] > ") == "MikroTik"
    assert hostname_from_prompt("FGT60F (global) # ") == "FGT60F"
    assert hostname_from_prompt("SSH@ICX7150>") == "ICX7150"
    assert hostname_from_prompt("admin@PA-220> ") == "PA-220"
    kv = parse_kv("Product Version.......................... 8.10.151.0\nUp Time : 10 days\nSoftware version  : 10.5.2.3\n")
    assert kv == {"Product Version": "8.10.151.0", "Up Time": "10 days", "Software version": "10.5.2.3"}


def test_parse_top_and_meminfo() -> None:
    new_top = "%Cpu(s):  2.3 us,  1.5 sy,  0.0 ni, 95.8 id,  0.2 wa\nMiB Mem :   3804.2 total,    245.5 free,   2112.2 used,   1446.5 buff/cache\n"
    cpu, total, used = parse_top(new_top)
    assert cpu == 4.2 and total == int(3804.2 * 1024**2) and used == int(2112.2 * 1024**2)
    old_top = "Cpu(s):  2.3%us,  1.5%sy,  0.0%ni, 90.0%id\nMem:   3895916k total,  3659836k used,   236080k free\n"
    cpu, total, used = parse_top(old_top)
    assert cpu == 10.0 and total == 3895916 * 1024 and used == 3659836 * 1024
    total, used = parse_meminfo("MemTotal:  2048000 kB\nMemFree:  100000 kB\nMemAvailable:  1024000 kB\n")
    assert total == 2048000 * 1024 and used == 1024000 * 1024


def test_fortios() -> None:
    status = (
        "Version: FortiGate-60F v7.2.5,build1517,230606 (GA.F)\nFirmware Signature: certified\n"
        "Serial-Number: FGT60FTK2009XXXX\nHostname: FGT-HQ\nVirtual domain configuration: disable\n"
    )
    assert fortinet.parse_system_status(status) == {
        "model": "FortiGate-60F", "os_version": "v7.2.5 build1517", "serial_number": "FGT60FTK2009XXXX", "hostname": "FGT-HQ",
    }
    perf = (
        "CPU states: 3% user 1% system 0% nice 96% idle 0% iowait 0% irq 0% softirq\n"
        "CPU0 states: 2% user 1% system 0% nice 97% idle 0% iowait 0% irq 0% softirq\n"
        "CPU1 states: 10% user 2% system 0% nice 88% idle 0% iowait 0% irq 0% softirq\n"
        "Memory: 1907272k total, 1101208k used (57.7%), 690252k free (36.2%), 115812k freeable (6.1%)\n"
        "Uptime: 40 days,  21 hours,  32 minutes\n"
    )
    cpus, memory, uptime = fortinet.parse_performance_status(perf)
    assert cpus == {0: 3.0, 1: 12.0}
    assert memory == {"total": 1907272 * 1024, "used": 1101208 * 1024}
    assert uptime == 40 * DAY + 21 * 3600 + 32 * 60
    _, old_memory, _ = fortinet.parse_performance_status("CPU states: 0% user 0% system 0% nice 100% idle\nMemory states: 25% used\n")
    assert old_memory == {"percent": 25.0}
    sensors = fortinet.parse_sensor_list(
        " 1 +3.3V            alarm=0  value=3.3112  threshold_status=0\n"
        " 5 PS1 VIN          alarm=0  value=230  threshold_status=0\n"
        " 8 FAN1             alarm=0  value=4800  threshold_status=0\n"
        " 9 FAN2             alarm=1  value=0  threshold_status=4\n"
        "10 DTS CPU0         alarm=0  value=45  threshold_status=0\n"
        "11 TD1              alarm=1  value=88  threshold_status=2\n"
        "12 CPU VCORE        alarm=0  value=1.1  threshold_status=0\n"
        "13 PS1 Status       alarm=0  value=0  threshold_status=0\n"
    )
    assert sensors["fans"] == {"FAN1": {"status": True, "rpm": 4800.0}, "FAN2": {"status": False, "rpm": 0.0}}
    assert sensors["temperature"] == {"DTS CPU0": {"temperature": 45.0, "alarm": False}, "TD1": {"temperature": 88.0, "alarm": True}}
    assert sensors["power"] == {"PS1 Status": {"status": True}}


def test_cisco_asa() -> None:
    version = (
        "Cisco Adaptive Security Appliance Software Version 9.16(4)\nDevice Manager Version 7.18(1)\n\n"
        "fw01 up 10 days 3 hours\n\nHardware:   ASA5516, 8192 MB RAM, CPU Atom C2000 series 2416 MHz, 1 CPU (8 cores)\n"
        "Serial Number: JAD2207812X\n"
    )
    facts = cisco.parse_asa_version(version)
    assert facts == {"os_version": "9.16(4)", "model": "ASA5516", "serial_number": "JAD2207812X", "hostname": "fw01", "uptime": 10 * DAY + 3 * 3600}
    assert cisco.parse_asa_cpu("CPU utilization for 5 seconds = 3%; 1 minute: 7%; 5 minutes: 5%") == 7.0
    assert cisco.parse_asa_memory("Free memory:        3896557576 bytes (71%)\nUsed memory:        1572843512 bytes (29%)\n") == (5469401088, 1572843512)
    env = cisco.parse_colon_environment(
        "Temperature:\n    Processors:\n        Processor 1: 61.0 C - OK (CPU1 Core Temperature)\n"
        "    Chassis:\n        Ambient 1: 79.5 C - WARNING (Chassis Back Temperature)\n"
        "Cooling Fans:\n    Cooling Fan 1: 6528 RPM - OK (Fan Speed Low)\n    Cooling Fan 2: 0 RPM - FAILED\n"
        "Power Supplies:\n    Left Slot (PS0): Present\n    Right Slot (PS1): Not Present\n"
    )
    assert env["temperature"]["Processor 1"] == {"temperature": 61.0, "alert": False, "critical": False}
    assert env["temperature"]["Ambient 1"]["alert"] is True
    assert env["fans"] == {"Cooling Fan 1": {"status": True}, "Cooling Fan 2": {"status": False}}
    assert env["power"] == {"Left Slot (PS0)": {"status": True}}


def test_cisco_aireos_and_smb() -> None:
    sysinfo = (
        "Product Version.................................. 8.10.151.0\nSystem Name...................................... WLC01\n"
        "System Up Time................................... 10 days 3 hrs 25 mins 10 secs\n"
        "Internal Temp Alarm Limits....................... 0 to 65 C\nInternal Temperature............................. +36 C\n"
    )
    info = cisco.parse_aireos_sysinfo(sysinfo)
    assert info["os_version"] == "8.10.151.0" and info["hostname"] == "WLC01"
    assert info["uptime"] == 10 * DAY + 3 * 3600 + 25 * 60 + 10
    assert info["_temperature"] == 36.0 and info["_temp_max"] == 65.0
    system = (
        "System Description:                       SG350-28P 28-Port Gigabit PoE Managed Switch\n"
        "System Up Time (days,hour:min:sec):       10,03:25:10\nSystem Name:                              sw01\n"
        "Unit     Temperature (Celsius)  Status\n----  ---------------------  ------\n 1            48                   OK\n"
    )
    facts = cisco.parse_smb_system(system)
    assert facts == {"hostname": "sw01", "model": "SG350-28P", "uptime": float(10 * DAY + 3 * 3600 + 25 * 60 + 10)}
    assert cisco.parse_smb_temperatures(system) == {"Unit 1": (48.0, False)}


def test_paloalto() -> None:
    info = paloalto.parse_system_info(
        "hostname: PA-220\nip-address: 192.168.1.1\nmodel: PA-220\nserial: 012345678901\nsw-version: 10.1.6\nuptime: 10 days, 3:25:01\n"
    )
    assert info == {"hostname": "PA-220", "model": "PA-220", "serial_number": "012345678901", "os_version": "10.1.6",
                    "uptime": 10 * DAY + 3 * 3600 + 25 * 60 + 1}
    env = paloalto.parse_environmentals(
        "----Thermal----\nSlot   Description                       Alarm  Degrees C  Min C    Max C\n"
        "1      Temperature near Cavium [U36]     False  39.0       5.0      60.0\n"
        "1      Temperature @ MP                  True   61.5       5.0      60.0\n"
        "----Fan Speed----\nSlot   Description                       Alarm  RPMs   Min RPM\n"
        "1      Fan #1 RPM                        False  2394   1000\n"
        "----Power----\nSlot   Description   Alarm  Volts  Min V  Max V\n1      Power: 1.0V   False  1.01   0.9    1.1\n"
        "----Power Supplies----\nSlot   Description                       Inserted     Alarm\n"
        "1      Power Supply #1 (left)            True         False\n"
        "1      Power Supply #2 (right)           False        False\n"
    )
    assert env["temperature"]["Temperature near Cavium [U36]"] == {"temperature": 39.0, "alert": False, "critical": False}
    assert env["temperature"]["Temperature @ MP"] == {"temperature": 61.5, "alert": True, "critical": True}
    assert env["fans"] == {"Fan #1 RPM": {"status": True}}
    assert env["power"] == {"Power Supply #1 (left)": {"status": True}}


def test_huawei() -> None:
    version = (
        "Huawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (S5720 V200R011C10SPC500)\n"
        "HUAWEI S5720-28X-SI-AC Routing Switch uptime is 102 days, 3 hours, 25 minutes\n"
    )
    facts = huawei.parse_vrp_version(version)
    assert facts == {"os_version": "V200R011C10SPC500", "model": "S5720-28X-SI-AC", "uptime": 102 * DAY + 3 * 3600 + 25 * 60}
    assert huawei.parse_vrp_cpu("CPU utilization for five seconds: 13%: one minute: 14%: five minutes: 13%") == 14.0
    assert huawei.parse_vrp_cpu("CPU Usage            : 12% Max: 99%") == 12.0
    total, used, pct = huawei.parse_vrp_memory(
        "System Total Memory Is: 508686336 bytes\nTotal Memory Used Is: 211435276 bytes\nMemory Using Percentage Is: 41%\n"
    )
    assert (total, used, pct) == (508686336, 211435276, 41.0)
    temps = huawei.parse_vrp_temperature(
        "Slot  Card   Sensor Status  Current(C)  Lower(C)  Lower    Upper(C)\n0     NA     NA     NORMAL  40          0         4        68\n"
        "1     NA     NA     ABNORMAL  71        0         4        68\n"
    )
    assert temps == {"Slot 0": (40.0, False), "Slot 1": (71.0, True)}
    assert huawei.parse_vrp_fans(" Slot  FanID   FanNum    Status      Speed\n 0     1       [1-1]     Normal      50%\n 0     2       [1-2]     Abnormal    0%\n") == {
        "Slot 0 Fan 1": True, "Slot 0 Fan 2": False,
    }
    assert huawei.parse_vrp_power("0     PWR1   YES      AC       Supply\n0     PWR2   NO       --       --\n0     PWR3   YES      AC       NotSupply\n") == {
        "PWR1": True, "PWR3": False,
    }


def test_comware() -> None:
    version = "HPE Comware Software, Version 7.1.070, Release 3208P08\nHPE 5130-24G-4SFP+ EI Switch uptime is 0 weeks, 2 days, 3 hours, 25 minutes\n"
    assert hpe.parse_comware_version(version) == {
        "os_version": "7.1.070 Release 3208P08", "model": "5130-24G-4SFP+ EI Switch", "uptime": 2 * DAY + 3 * 3600 + 25 * 60,
    }
    assert hpe.parse_comware_cpu("Slot 1 CPU 0 CPU usage:\n       6% in last 5 seconds\n       7% in last 1 minute\n") == [7.0]
    mem7 = "Slot 1:\n             Total      Used      Free    Shared   Buffers    Cached   FreeRatio\nMem:       1004104    482888    521216         0      1940    132384       64.6%\n-/+ Buffers/Cache:    348564    655540\n"
    assert hpe.parse_comware_memory(mem7) == ((348564 + 655540) * 1024, 348564 * 1024)
    assert hpe.parse_comware_memory("System Total Memory(bytes): 431907344\nTotal Used Memory(bytes): 172113900\n") == (431907344, 172113900)
    env = hpe.parse_comware_environment(
        " System temperature information (degree centigrade):\n Slot  Sensor    Temperature  Lower  Warning  Alarm  Shutdown\n"
        " 1     hotspot 1  38           0      85       95     NA\n"
    )
    assert env == {"Slot 1 hotspot 1": {"temperature": 38.0, "warn": 85.0, "crit": 95.0}}
    assert hpe.parse_comware_fans(" Slot 1:\n Fan 1:\n State    : Normal\n Fan 2:\n State    : Fault\n") == {"Fan 1": True, "Fan 2": False}


def test_procurve() -> None:
    system = (
        "  System Name        : branch-sw01\n"
        "  Software revision  : WC.16.11.0012        Base MAC Addr      : 001122-334455\n"
        "  ROM Version        : WC.16.01.0008        Serial Number      : CN12345678\n\n"
        "  Up Time            : 10 days              Memory   - Total   : 333,447,168\n"
        "  CPU Util (%)       : 4                               Free    : 196,148,128\n\n"
        "  IP Mgmt  - Pkts Rx : 123                  Packet   - Total   : 6600\n"
        "             Pkts Tx : 456                  Buffers    Free    : 4316\n"
    )
    facts = hpe.parse_procurve_system(system)
    assert facts["hostname"] == "branch-sw01" and facts["os_version"] == "WC.16.11.0012"
    assert facts["serial_number"] == "CN12345678" and facts["uptime"] == 10 * DAY
    assert facts["_cpu"] == 4.0 and facts["_mem"] == (333447168, 333447168 - 196148128)
    assert hpe.parse_procurve_temperature(" Chassis| 29C      33C  25C   55C        NO\n") == {"Chassis": (29.0, 55.0, False)}
    assert hpe.parse_procurve_fans("Sys-1  | Fan OK      | 0\nSys-2  | Fan Failed  | 2\n") == {"Sys-1": True, "Sys-2": False}
    assert hpe.parse_procurve_power("  1     J9737A    CN12345678  Powered         AC 120V/240V  85  1050\n  2                           Not Present     --  0  0\n") == {"PS 1": True}


def test_aoscx() -> None:
    system = (
        "Hostname                        : nyc-sw01\nProduct Name                    : JL658A 6300M 24SFP+ 4SFP56 Swch\n"
        "Chassis Serial Nbr              : SG12345678\nUp Time                         : 1 week, 2 days, 3 hours, 4 minutes\n"
        "CPU Util (%)                    : 5\nMemory Usage (%)                : 25\n"
    )
    facts = hpe.parse_aoscx_system(system)
    assert facts["hostname"] == "nyc-sw01" and facts["serial_number"] == "SG12345678"
    assert facts["uptime"] == 9 * DAY + 3 * 3600 + 240 and facts["_cpu"] == 5.0 and facts["_mem"] == 25.0
    temps = hpe.parse_aoscx_temperature(
        "Mbr/Slot-Sensor                 Module Type      temperature  Status\n"
        "1/1-PHY-01-04                   line-card-module  51.00 C     normal\n"
        "1/1-Switch-ASIC-Internal        line-card-module  91.88 C     critical\n"
    )
    assert temps == {"1/1-PHY-01-04": (51.0, "normal"), "1/1-Switch-ASIC-Internal": (91.88, "critical")}
    rows = hpe.parse_aoscx_status_rows("1/1      JL085A   CN12345678  OK   AC  100V-240V  250\n1/2      N/A      N/A         Absent  --  --  0\n1/3      N/A      N/A  fault\n")
    assert rows == {"1/1": True, "1/3": False}


def test_mikrotik() -> None:
    v7 = "Columns: NAME, VALUE, TYPE\n#  NAME             VALUE  TYPE\n0  cpu-temperature  52     C\n1  fan1-speed       3000   RPM\n2  fan2-speed       0      RPM\n3  psu1-state       ok\n4  psu2-state       fail\n"
    health = mikrotik.parse_routeros_health(v7)
    assert health == {"temperature": {"cpu-temperature": 52.0}, "fans": {"fan1-speed": True, "fan2-speed": False}, "power": {"psu1-state": True, "psu2-state": False}}
    v6 = "          voltage: 24.1V\n      temperature: 41C\n  cpu-temperature: 55C\n       fan1-speed: 3600RPM\n"
    assert mikrotik.parse_routeros_health(v6) == {"temperature": {"temperature": 41.0, "cpu-temperature": 55.0}, "fans": {"fan1-speed": True}, "power": {}}
    kv = mikrotik.parse_routeros_kv("                   uptime: 1w2d3h25m10s\n                  version: 7.13 (stable)\n             total-memory: 1024.0MiB\n")
    assert kv == {"uptime": "1w2d3h25m10s", "version": "7.13 (stable)", "total-memory": "1024.0MiB"}


def test_dell_os10() -> None:
    assert dell.parse_os10_version("OS Version: 10.5.2.3\nSystem Type: S5248F-ON\nUp Time: 10 days 03:25:10\n") == {
        "os_version": "10.5.2.3", "model": "S5248F-ON", "uptime": 10 * DAY + 3 * 3600 + 25 * 60 + 10,
    }
    assert dell.parse_os10_inventory("Product Serial Number : CN0ABC123\n") == "CN0ABC123"
    thermal = dell.parse_os10_thermal(
        "Unit    State         Temperature\n1       up            43\n\nThermal sensors\nUnit   Sensor-Id       Sensor-name                                 Temperature\n"
        "------------------------------------------------------------------------------\n1      1               CPU On-Board temp sensor                    32\n1      2               Switch board temp sensor                    28\n"
    )
    assert thermal == {"Unit 1 CPU On-Board temp sensor": 32.0, "Unit 1 Switch board temp sensor": 28.0}
    system = (
        "-- Power Supplies --\nPSU-ID  Status      Type    AirFlow   Fan  Speed(rpm)  Status\n------\n1       up          AC      NORMAL    1    7056        up\n2       fail\n"
        "-- Fan Status --\nFanTray  Status      AirFlow   Fan  Speed(rpm)  Status\n------\n1        up          NORMAL    1    8946        up\n"
    )
    assert dell.parse_os10_system(system) == {"power": {"PSU 1": True, "PSU 2": False}, "fans": {"Fan tray 1": True}}


def test_extreme_exos() -> None:
    switch = 'SysName:          "X440G2"\nSystem Type:      X440G2-48p-10G4\nSystem UpTime:    10 days 3 hours 25 minutes 10 seconds\nPrimary ver:      30.7.1.1\nSecondary ver:    30.6.1.11\nImage Booted:     primary\n'
    assert extreme.parse_exos_switch(switch) == {"hostname": "X440G2", "model": "X440G2-48p-10G4", "os_version": "30.7.1.1",
                                                 "uptime": 10 * DAY + 3 * 3600 + 25 * 60 + 10}
    assert extreme.parse_exos_cpu("System              4.3  3.9  3.8  3.7  3.7  3.8  3.8  42.8      0.00   0.00\n") == 3.7
    assert extreme.parse_exos_memory("Total DRAM (KB): 1048576\nSystem (KB): 34160\nUser (KB): 418708\nFree (KB): 595708\n") == (1048576 * 1024, (1048576 - 595708) * 1024)
    temps = extreme.parse_exos_temperature("Field Replaceable Units               Temp (C)   Status   Min  Normal  Max\nSwitch          : X440G2-48p-10G4      42.0      Normal   -10  0-52    57\n")
    assert temps == {"Switch": (42.0, "normal", 57.0)}
    fans = extreme.parse_exos_fans("FanTray information:\nState:                 Operational\nFan-1:                 Operational at 5880 RPM\nFan-2:                 Failed\n")
    assert fans == {"Fan-1": True, "Fan-2": False}
    power = extreme.parse_exos_power("PowerSupply 1 information:\nState:                 Powered On\nPowerSupply 2 information:\nState:                 Empty\n")
    assert power == {"PowerSupply 1": True}


def test_ruckus_fastiron() -> None:
    version = "  SW: Version 08.0.95dT213 \n  HW: Stackable ICX7150-48P-4X1G\n  Serial  #:FEK3224Q0XX\nThe system uptime is 10 days 3 hours 25 minutes 10 seconds\n"
    assert ruckus.parse_fastiron_version(version) == {"os_version": "08.0.95dT213", "model": "ICX7150-48P-4X1G", "serial_number": "FEK3224Q0XX",
                                                      "uptime": 10 * DAY + 3 * 3600 + 25 * 60 + 10}
    assert ruckus.parse_fastiron_cpu("1 percent busy, from 3 sec ago\n60  sec avg:  4 percent busy\n") == 4.0
    assert ruckus.parse_fastiron_memory("Total DRAM: 1073741824 bytes\n  Dynamic memory: 1001308160 bytes total, 579739648 bytes free, 42% used\n") == (1001308160, 1001308160 - 579739648)
    chassis = ruckus.parse_fastiron_chassis(
        "The stack unit 1 chassis info:\n\nPower supply 1 (AC - PoE) present, status ok\nPower supply 2 not present\n\nFan 1 ok, speed (auto):  [[1]]<->2\nFan 2 failed\n\n"
        "Sensor A Temperature Readings:\n        Current temperature : 33.5 deg-C\nSensor B Temperature Readings:\n        Current temperature : 37.0 deg-C\n"
        "        Warning level.......: 75.0 deg-C, shutdown level: 85.0 deg-C\n"
    )
    assert chassis["power"] == {"Unit 1 PSU 1": True}
    assert chassis["fans"] == {"Unit 1 Fan 1": True, "Unit 1 Fan 2": False}
    assert chassis["temperature"] == {"Unit 1 Sensor A": 33.5, "Unit 1 Sensor B": 37.0}
    assert (chassis["warn"], chassis["shutdown"]) == (75.0, 85.0)


def test_checkpoint_gaia() -> None:
    sysenv = checkpoint.parse_gaia_sysenv(
        "Name                         Value     unit      type           status    Maximum   Minimum\n"
        "+3.3V                        3.33      Volt      Voltage        0         3.63      2.97\n"
        "CPU1 Temperature             46.00     Celsius   Temperature    0         80.00     0.00\n"
        "Fan1                         5400.00   RPM       Fan            0         0.00      1000.00\n"
        "Fan2                         0.00      RPM       Fan            1         0.00      1000.00\n"
        "Power Supply 1               1         N/A       PowerSupply    0\n"
    )
    assert sysenv["temperature"] == {"CPU1 Temperature": {"temperature": 46.0, "alert": False, "max": 80.0}}
    assert sysenv["fans"] == {"Fan1": True, "Fan2": False}
    assert sysenv["power"] == {"Power Supply 1": True}
    assert checkpoint.parse_gaia_uptime(" 10:00:00 up 10 days,  3:25,  1 user,  load average: 0.00, 0.01, 0.05") == 10 * DAY + 3 * 3600 + 25 * 60


def test_vyos_linux_helpers() -> None:
    assert vyos.parse_proc_uptime("3600.52 7200.11\n") == 3600.52
    assert vyos.parse_thermal_zones("45000\n52500\n") == {"thermal_zone0": 45.0, "thermal_zone1": 52.5}
