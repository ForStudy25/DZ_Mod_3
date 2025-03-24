import json
import base64
import pathlib

import requests

REPORT_FILE = pathlib.Path("report_part_1.txt")
API_KEY = "385a66c6ba28cf51d104891d87dc854014620af055a4ffd4451ba2882ab61b23"
AV_LIST = ["Fortinet", "McAfee", "Yandex", "Sophos"]

class ScanClass:
    
    def __init__(self, api_key, file: pathlib.Path):
        self._api_key = api_key
        self.file: pathlib.Path = file
        self.file_id: str = ""
        
        self.vendors: list[VendorResultClass] = []
        self.mal_vendors: list[VendorResultClass] = []
        
        self.contacted_ips = []
        self.contacted_domains = []
        
        self.files_opened = []
        self.files_written = []
        self.files_deleted = []
        self.files_dropped = []
        # self.behavior
    
    def upload_file(self):
        files = { "file": (self.file.name, open(self.file.__str__(), "rb"), "application/x-zip-compressed") }
        r = requests.post(
            "https://www.virustotal.com/api/v3/files",
            data={"password": "netology"},
            files=files,
            headers={
                "accept": "application/json",
                "x-apikey": self._api_key
            }
        )
        js = json.loads(r.text)
        self.file_id = base64.b64decode(js["data"]["id"]).decode("utf-8").split(":")[0]

    def get_vendors_scan_result(self):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{self.file_id}",
            headers={"x-apikey": self._api_key}
        )
        js = json.loads(r.text)
        # print(js)

        results = js["data"]["attributes"]["last_analysis_results"]
        for name in results:
            vendor = VendorResultClass(
                results[name]["engine_name"],
                results[name]["category"],
                results[name]["result"]
            )
            self.vendors.append(vendor)
            if vendor.category == "malicious":
                self.mal_vendors.append(vendor)

    def get_contacted_ips(self):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{self.file_id}/contacted_ips",
            headers={"x-apikey": self._api_key}
        )
        js = json.loads(r.text)
        # print(js)
        for data in js["data"]:
            self.contacted_ips.append(data["id"])
        
    def get_contacted_domains(self):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{self.file_id}/contacted_domains",
            headers={"x-apikey": self._api_key}
        )
        js = json.loads(r.text)
        # print(js)
        for data in js["data"]:
            self.contacted_domains.append(data["id"])
    
    def get_behaviours(self):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{self.file_id}/behaviours",
            headers={"x-apikey": self._api_key}
        )
        js = json.loads(r.text)
        # print(js)
 
        for data in js["data"]:
            if "files_opened" in data["attributes"]:
                for f in data["attributes"]["files_opened"]:
                    self.files_opened.append(f)
            if "files_written" in data["attributes"]:
                for f in data["attributes"]["files_written"]:
                    self.files_written.append(f)
            if "files_deleted" in data["attributes"]:
                for f in data["attributes"]["files_deleted"]:
                    self.files_deleted.append(f)
            if "files_dropped" in data["attributes"]:
                for f in data["attributes"]["files_dropped"]:
                    self.files_dropped.append(f["path"])
    
    # def get_behaviours(self):
    #     r = requests.get(
    #         f"https://www.virustotal.com/api/v3/files/{self.file_id}/behaviours",
    #         headers={"x-apikey": self._api_key}
    #     )
    #     js = json.loads(r.text)
    #     print(js)

    def start(self):
        self.upload_file()
        self.get_vendors_scan_result()
        self.get_contacted_ips()
        self.get_contacted_domains()
        self.get_behaviours()

    def did_vendor_find_malware(self, target_vendor: str) -> bool:
        if target_vendor in [vendor.name for vendor in self.mal_vendors]:
            return True
        return False
    
    def generate_report(self, path: pathlib.Path):
        with open(path.__str__(), "w+", encoding="utf-8") as f:
            del_str = "#" * 250
            f.write(f"{del_str}\n")
            f.write(f"Результат сканирования вредоносного файла\n")
            f.write(f"{del_str}\n")
            
            f.write(f"Список вендоров и результат их сканирования:\n")
            for vendor in self.mal_vendors:
                f.write(f"\t{vendor.name.ljust(25)}\t{vendor.result}\n")
            f.write(f"{del_str}\n")
            
            f.write(f"Список вендоров, которые обнаружили угрозу:\n")
            f.write(f"\t{', '.join([v.name for v in self.mal_vendors])}\n")
            f.write(f"{del_str}\n")
            
            f.write(f"Сравнение результатов с заданным списком антивирусов и песочниц:\n")
            for av in AV_LIST:
                f.write(f"\t{av.ljust(15)}\t{'Обнаружил' if self.did_vendor_find_malware(av) else 'Не обнаружил'}\n")
            f.write(f"{del_str}\n")
            
            f.write(f"Адреса и домены, с которыми контактирует вредоносный файл:\n")
            if len(self.contacted_ips) > 0:
                f.write(f"\tIP-адреса:\n")
                for ip in self.contacted_ips:
                    f.write(f"\t\t{ip}\n")
            if len(self.contacted_domains) > 0:
                f.write(f"\tДомены:\n")
                for domain in self.contacted_domains:
                    f.write(f"\t\t{domain}\n") 
            f.write(f"{del_str}\n")
            
            f.write(f"Данные из песочницы о взаимодействии вредоносного файла с другими файлами (запись, удаление):\n")
            # if len(self.files_opened) > 0:
            #     f.write(f"\tOpened:\n")
            #     for file in self.files_opened:
            #         f.write(f"\t\t{file}\n")
            if len(self.files_written) > 0:
                f.write(f"\tWritten:\n")
                for file in self.files_written:
                    f.write(f"\t\t{file}\n")
            if len(self.files_deleted) > 0:
                f.write(f"\tDeleted:\n")
                for file in self.files_deleted:
                    f.write(f"\t\t{file}\n")
            if len(self.files_dropped) > 0:
                f.write(f"\tDropped:\n")
                for file in self.files_dropped:
                    f.write(f"\t\t{file}\n")
            f.write(f"{del_str}\n")


class VendorResultClass:

    def __init__(self, name: str, category, result):
        self.name = name
        self.category = category
        self.result = result


def main():
    file_for_scan = pathlib.Path("protected_archive.zip")
    scan = ScanClass(API_KEY, file_for_scan)
    scan.start()
    scan.generate_report(REPORT_FILE)


if __name__ == "__main__":
    main()
