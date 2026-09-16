import ipaddress
import dns.resolver
import os
import json
import zipfile
import re

from urllib.parse import urlparse
from prettytable import PrettyTable


class EmailClassification:
    test = 0

    REQUIRED_FIELDS = {
        "id",
        "datetime",
        "sender",
        "subject",
        "attachment",
        "text",
    }

    SUSPICIOUS_WORDS = {
        "пароль",
        "подтвердите",
        "подтверждение",
        "разблокировать",
        "заблокирован",
        "безопасность",
        "верификация",
    }

    def __init__(self, zip_archive):
        self.zip_archive = zip_archive
        self.table = PrettyTable()


    def open_zip(self):
        with zipfile.ZipFile(self.zip_archive) as archive:
            directory = archive.filelist[0]

            for filename in os.listdir(directory.filename):
                try:
                    filepath = os.path.join(directory.filename, filename)
                    with archive.open(filepath) as file:
                        data = json.load(file)

                    missing = self.REQUIRED_FIELDS - data.keys()

                    if missing:
                        print(f"{filename}: отсутсвуют поля {missing}")
                        continue
                    else:
                        print(f"{filename} ОК")

                    phishing_coeff = self.calculate_phishing_coeff(data)

                    self.test += phishing_coeff

                    if phishing_coeff <= 3.5:
                        print(f"письмо {filename} НЕ является фишинговым")
                    elif 3.5 < phishing_coeff <= 5:
                        print(f"письмо {filename} является подозрительным")
                    else:
                        print(print(f"письмо {filename} является фишинговым"))

                except json.JSONDecodeError:
                    print(f"{filename} некорректный JSON")

            print(self.table)

    def calculate_phishing_coeff(self, data):
        domain = data['sender'].split("@")[1]

        http_url = 0
        ip_addr = False
        urls = self.__extract_urls_from_text(data['text'])
        has_difference_domain = self.has_different_domain(domain, urls)
        for url in urls:
            if self.__is_http(url):
                http_url += 1
            if self.__is_ip_url(url):
                ip_addr = True

        all_urls = len(urls)


        coeff = 0
        features = {
            "no_spf": 0.25 if not self.__check_spf(domain) else 0,
            "no_mx": 0.5 if not self.__check_mx(domain) else 0,
            "http_urls": 2 + http_url/all_urls if http_url > 0 else 0,
            "ip_urls": 2 if ip_addr else 0,
            "suspicious_words": 0.5 * len(self.find_suspicious_words(data['text'], data['subject'])),
            "url_domain_difference": 2 if has_difference_domain else 0,
        }


        for weight in features.values():
            coeff += weight

        self.make_table(data["id"], features, coeff)

        return coeff


    def make_table(self,id, features, coeff):
        self.table.field_names = ["id",features.keys(),"total_coeff"]
        self.table.add_row([id, features.values(), coeff])



    def has_different_domain(self, domain, urls) -> bool:
        if not urls:
            return False
        for url in urls:
            hostname = urlparse(url).hostname
            if hostname == domain or hostname.endswith(f".{domain}"):
                return False

        return True

    def find_suspicious_words(self,text: str, subject: str) -> list[str]:
        text = text.lower()
        subject = subject.lower()

        return [
            word
            for word in self.SUSPICIOUS_WORDS
            if word in text or word in subject
        ]

    @staticmethod
    def __check_spf(domain) -> bool:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    print(txt_record)
                    return True
            print('SPF-запись не найдена')
        except dns.resolver.NXDOMAIN:
            print(f"Домен {domain} не существует.")
        except Exception as e:
            print(f"Произошла ошибка: {e}")

        return False

    @staticmethod
    def __check_mx(domain: str) -> bool:
        try:
            answers = dns.resolver.resolve(domain, "MX")

            for rdata in answers:
                print(rdata.exchange, rdata.preference)

            return True

        except dns.resolver.NXDOMAIN:
            print(f"Домен {domain} не существует.")
        except dns.resolver.NoAnswer:
            print(f"У домена {domain} нет MX-записи.")
        except Exception as e:
            print(f"Произошла ошибка: {e}")

        return False

    @staticmethod
    def __extract_urls_from_text(text: str) -> set[str]:
        return set(re.findall(r"https?://[^\s]+", text))

    @staticmethod
    def __is_http(url: str) -> bool:
        return urlparse(url).scheme == "http"

    @staticmethod
    def __is_ip_url(url: str) -> bool:
        hostname = urlparse(url).hostname

        if hostname is None:
            return False

        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False


a = EmailClassification("letters.zip")
a.open_zip()
print(a.test)
print(f"Средний коэффициент фишинга: {a.test/37}")