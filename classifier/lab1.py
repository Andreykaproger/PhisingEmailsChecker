import ipaddress
import dns.asyncresolver
import json
import zipfile
import re
import asyncio
from typing import cast

from urllib.parse import urlparse


class EmailClassification:
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


    async def open_zip(self) -> list[dict[str, str | float]]:
        tasks = []
        with zipfile.ZipFile(self.zip_archive) as archive:
            for filename in archive.namelist():
                if filename.startswith("__MACOSX"):
                    continue
                if not filename.endswith(".json"):
                    continue

                tasks.append(self.process_email(filename, archive))

            results = await asyncio.gather(*tasks)

        results = cast(list[dict[str, str]], cast(object, results))

        return results


    async def calculate_phishing_coeff(self, data):
        domain = data['sender'].rsplit("@",1)[1]

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

        spf, mx = await asyncio.gather(
            self.__check_spf(domain),
            self.__check_mx(domain),
        )

        coeff = 0
        features = {
            "no_spf": 0.25 if not spf else 0,
            "no_mx": 0.5 if not mx else 0,
            "http_urls": 2 + http_url/all_urls if http_url > 0 else 0,
            "ip_urls": 2 if ip_addr else 0,
            "suspicious_words": 0.5 * len(self.find_suspicious_words(data['text'], data['subject'])),
            "url_domain_difference": 2 if has_difference_domain else 0,
        }


        for weight in features.values():
            coeff += weight

        return coeff


    async def process_email(self, filename, archive) -> dict[str, str | float]:
        try:
            with archive.open(filename) as file:
                data = json.load(file)

            missing = self.REQUIRED_FIELDS - data.keys()

            if missing:
                return {
                    "id": f"{filename}",
                    "error": f"Отсутствуют поля {missing}"
                }
        except json.JSONDecodeError:
            return {
                "id": filename.split("/")[1],
                "error": "Некорректный JSON"
            }

        phishing_coeff = await self.calculate_phishing_coeff(data)

        if phishing_coeff <= 3.5:
            status = "OK"
        elif phishing_coeff <= 5:
            status = "Подозрительное"
        else:
            status = "Фишинг"

        return {
            "id": data["id"],
            "coefficient": phishing_coeff,
            "status": status,
        }


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
    async def __check_spf(domain) -> bool:
        try:
            answers = await dns.asyncresolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    print(txt_record)
                    return True
            print('SPF-запись не найдена')
        except dns.asyncresolver.NXDOMAIN:
            print(f"Домен {domain} не существует.")
        except Exception as e:
            print(f"Произошла ошибка: {e}")

        return False


    @staticmethod
    async def __check_mx(domain: str) -> bool:
        try:
            answers = await dns.asyncresolver.resolve(domain, "MX")

            for rdata in answers:
                print(rdata.exchange, rdata.preference)

            return True

        except dns.asyncresolver.NXDOMAIN:
            print(f"Домен {domain} не существует.")
        except dns.asyncresolver.NoAnswer:
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