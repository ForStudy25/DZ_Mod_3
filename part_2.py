import pathlib

import vulners
# import requests

REPORT_FILE = pathlib.Path("report_part_2.txt")
API_KEY = "XF45KOWQ5H3HHK3OZT0CKFKGSK446LV6JM80SXJ0JS3BDY8RXIIGGT150GRGPPI2"
TARGET_PROGRAMS = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    # В условии задания указан "7zip", однако, Vulners находит уязвимости только если исправить на "7-zip"
    {"Program": "7-zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]


class VulnersClass:
    
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self.api = vulners.Vulners(api_key=api_key)

    def scan_software_list(self, softwares: list) -> list:
        return self.api.audit_software(software=softwares)

    def get_available_exploits(self, cve: str) -> list:
        return self.api.find_exploit_all(cve)


class VulnerabiliryClass:
    
    def __init__(self, cve: str) -> None:
        self.cve: str = cve
        self.exploits: list[ExploitClass] = []
    
    def get_exploits_count(self) -> int:
        return len(self.exploits)
    
    def __str__(self) -> str:
        return self.cve


class ExploitClass:
    
    def __init__(
        self,
        title: str,
        type: str,
        published: str,
        href: str,
        vhref: str
    ) -> None:
        self.title: str = title
        self.type: str = type
        self.published: str = published
        self.href: str = href
        self.vhref: str = vhref


class SoftwareClass:
    
    def __init__(self, name: str, version: str) -> None:
        self.name: str = name
        self.version: str = version
        self.cpe: str = None
        self.vulnerabilities: list[VulnerabiliryClass] = []
    
    def get_vulnerabilities_count(self) -> int:
        return len(self.vulnerabilities)
    
    def is_contain_any_exploit(self) -> bool:
        for vuln in self.vulnerabilities:
            if vuln.get_exploits_count():
                return True
        return False
    
    def __str__(self):
        return f"{self.name} v{self.version}"


class SoftwareScanClass:
    
    def __init__(self, api_key: str) -> None:
        self.vulners_api: VulnersClass = VulnersClass(api_key)
        self.softwares: list[SoftwareClass] = []
        # self.vulnerabilities: list[VulnerabiliryClass] = []

    def start_scan_softwares(self, target_softwares: list) -> None:
        target_softwares_for_scan = []
        
        for software in target_softwares:
            self.softwares.append(SoftwareClass(software['Program'], software['Version']))
            target_softwares_for_scan.append(
                {
                    "product": software["Program"],
                    "version": software["Version"] 
                }
            )
        
        scan_result = self.vulners_api.scan_software_list(target_softwares_for_scan)
        for info in scan_result:
            for software in self.softwares:
                if info["input"]["product"] == software.name and info["input"]["version"] == software.version:
                    software.cpe = info["matched_criteria"]
                    for vuln in info["vulnerabilities"]:
                        software.vulnerabilities.append(VulnerabiliryClass(vuln["id"])) 
                    break     

    # def start_scan_for_available_exploits(self) -> None:
    #     for software in self.softwares:
    #         for vuln in software.vulnerabilities:
    #             exploits = self.vulners_api.get_available_exploits(vuln.cve)
    #             for exploit in exploits:
    #                 vuln.exploits.append(
    #                     ExploitClass(
    #                         exploit["title"],
    #                         exploit["type"],
    #                         exploit["published"],
    #                         exploit["href"],
    #                         exploit["vhref"],
    #                     )
    #                 )

    def start_scan_software_for_available_exploits(self, software: SoftwareClass) -> None:
        for vuln in software.vulnerabilities:
            exploits = self.vulners_api.get_available_exploits(vuln.cve)
            for exploit in exploits:
                vuln.exploits.append(
                    ExploitClass(
                        exploit["title"],
                        exploit["type"],
                        exploit["published"],
                        exploit["href"],
                        exploit["vhref"],
                    )
                )

    def start_full_scan(self, target_softwares: list) -> None:
        self.start_scan_softwares(target_softwares)
        
        # Делает слишком много запросов, по 1 на каждую уязвимость (выходит около 4000),
        # лимита trial версии не хватает
        # self.start_scan_cve__for_available_exploits()
        
        for software in self.softwares:
            if software.name == "Google Chrome" or software.name == "Mozilla Firefox":
                continue
            self.start_scan_software_for_available_exploits(software)

    def write_vulnerability_list(self, f, software: SoftwareClass) -> None:
        length = software.get_vulnerabilities_count()
        vulns = software.vulnerabilities
        
        for i in range(length):
            if i % 10 == 0:
                f.write("\t\t")
            if i == length - 1:
                f.write(f"{vulns[i]}\n")
                break
            f.write(f"{vulns[i]}, ")
            if i % 10 == 9:
                f.write("\n")
    
    def write_vulnerability_with_exploits(self, f, software: SoftwareClass) -> None:
        vulns = software.vulnerabilities
        
        for vuln in vulns:
            f.write(f"\t\t{vuln.cve}\n")
            for exploit in vuln.exploits:
                f.write(f"\t\t\t{exploit.vhref}\n")

    def generate_report(self, path: pathlib.Path) -> None:
        del_str = "#" * 200

        with open(str(path), "w+", encoding="utf-8") as f:
            f.write(f"{del_str}\n")
            f.write("Отчет об анализе приложений\n")
            f.write(f"{del_str}\n")
            
            for software in self.softwares:
                f.write(f"Name:\t\t\t{software.name}\n")
                f.write(f"Version:\t\t{software.version}\n")
                f.write(f"CPE:\t\t\t{software.cpe if software.cpe is not None else 'not found'}\n")
                vuln_count = software.get_vulnerabilities_count()
                f.write(f"Vuln count:\t\t{vuln_count if vuln_count != 0 else 'not found'}\n")
                
                if vuln_count > 0:
                    f.write(f"Vulnerabilities List:\n")
                    if software.is_contain_any_exploit():
                        self.write_vulnerability_with_exploits(f, software)
                    else:
                        self.write_vulnerability_list(f, software)
                f.write(f"{del_str}\n")


def main():
    scan = SoftwareScanClass(API_KEY)
    scan.start_full_scan(TARGET_PROGRAMS)
    scan.generate_report(REPORT_FILE)

    input()
    

if __name__ == "__main__":
    main()
