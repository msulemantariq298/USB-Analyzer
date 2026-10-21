from usb_analyzer.device_monitor.windows import WindowsWmiProvider


class FakeWmiObject:
    def __init__(self, **properties) -> None:
        self.__dict__.update(properties)
        self._associations = {}

    def set_associations(self, association_class: str, objects: list) -> None:
        self._associations[association_class] = objects

    def associators(self, association_class: str) -> list:
        return self._associations.get(association_class, [])


class FakeWmiConnection:
    def __init__(self, entities: list, disks: list) -> None:
        self.entities = entities
        self.disks = disks
        self.disk_queries = 0

    def query(self, query: str) -> list:
        assert "Win32_PnPEntity" in query
        return self.entities

    def Win32_DiskDrive(self) -> list:
        self.disk_queries += 1
        return self.disks


def test_provider_maps_usb_disk_partitions_to_drive_roots() -> None:
    device_id = r"USBSTOR\DISK&VEN_DEMO&PROD_DRIVE\SERIAL"
    entity = FakeWmiObject(
        PNPDeviceID=device_id,
        Name="Demo USB drive",
        Manufacturer="Example",
        PNPClass="DiskDrive",
        Service="disk",
        HardwareID=[],
        Status="OK",
    )
    logical_disk = FakeWmiObject(DeviceID="E:")
    partition = FakeWmiObject()
    partition.set_associations("Win32_LogicalDiskToPartition", [logical_disk])
    usb_disk = FakeWmiObject(PNPDeviceID=device_id)
    usb_disk.set_associations("Win32_DiskDriveToDiskPartition", [partition])
    unrelated_disk = FakeWmiObject(PNPDeviceID=r"SCSI\DISK\OTHER")
    unrelated_disk.set_associations("Win32_DiskDriveToDiskPartition", [])
    connection = FakeWmiConnection([entity], [usb_disk, unrelated_disk])
    provider = object.__new__(WindowsWmiProvider)
    provider._connection = connection

    devices = provider.list_devices()

    assert devices[device_id].volume_paths == ("E:\\",)
    assert connection.disk_queries == 1


def test_provider_leaves_device_without_mounted_volume_unscannable() -> None:
    device_id = r"USBSTOR\DISK&VEN_DEMO&PROD_DRIVE\SERIAL"
    entity = FakeWmiObject(
        PNPDeviceID=device_id,
        Name="Demo USB drive",
        HardwareID=[],
    )
    usb_disk = FakeWmiObject(PNPDeviceID=device_id)
    usb_disk.set_associations("Win32_DiskDriveToDiskPartition", [])
    connection = FakeWmiConnection([entity], [usb_disk])
    provider = object.__new__(WindowsWmiProvider)
    provider._connection = connection

    devices = provider.list_devices()

    assert devices[device_id].volume_paths == ()
