"""Import/Export Services - CSV, KeePass, XML formats"""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.account import Account, AccountToTag, Tag, Category, Client, User
from app.models.custom_field import CustomFieldValue
from app.core.security import EncryptionService
from datetime import UTC, datetime
import csv
import logging
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET
try:
    from defusedxml.ElementTree import fromstring as parse_xml_safely
except ModuleNotFoundError:  # pragma: no cover - environment-dependent fallback
    parse_xml_safely = ET.fromstring
import base64
import hashlib
import hmac
import time
import uuid

from app.core.defuse_compat import (
    decrypt_account_pass,
    decrypt_with_password,
    encrypt_account_pass,
    encrypt_with_password,
)
from app.core.syspass_runtime_config import get_password_salt
from app.services.auth_service import get_password_hash
from app.services.category_service import make_item_hash

logger = logging.getLogger(__name__)


class ImportService:
    """Base import service with common functionality"""

    def __init__(self, db: Session, encryption_service: EncryptionService, user_id: int):
        self.db = db
        self.encryption = encryption_service
        self.user_id = user_id
        self.imported_accounts = []
        self.errors = []

    def _encrypt_password(self, password: str) -> tuple:
        """Encrypt password using the encryption service"""
        encrypted = self.encryption.encrypt(password)
        return encrypted, b""  # Empty key identifies the Python AES fallback.

    def _user_group_id(self) -> int:
        user = self.db.get(User, self.user_id)
        return user.userGroupId if user else 1

    def _get_or_create_category(self, name: str) -> Category:
        """Get existing category or create new one"""
        result = self.db.execute(
            select(Category).where(Category.name == name)
        ).scalars().first()

        if not result:
            result = Category(name=name, hash=make_item_hash(name))
            self.db.add(result)
            self.db.flush()

        return result

    def _get_or_create_client(self, name: str, contact: str = None, notes: str = None) -> Client:
        """Get existing client or create new one"""
        result = self.db.execute(
            select(Client).where(Client.name == name)
        ).scalars().first()

        if not result:
            result = Client(
                name=name,
                description=notes,
                hash=make_item_hash(name),
            )
            # PHP has no persisted client contact column. Keep the compatibility
            # property populated for the lifetime of this ORM instance only.
            result.contact = contact
            self.db.add(result)
            self.db.flush()

        return result

    def _get_or_create_tag(self, name: str, color: str = '#000000') -> Tag:
        """Get or create tag"""
        result = self.db.execute(
            select(Tag).where(Tag.name == name)
        ).scalars().first()

        if not result:
            result = Tag(name=name, hash=make_item_hash(name))
            result.color = color
            self.db.add(result)
            self.db.flush()

        return result

    def import_accounts(self, data: List[Dict[str, Any]]) -> Dict[str, int]:
        """Import accounts from parsed data"""
        stats = {'success': 0, 'failed': 0, 'skipped': 0}

        for item in data:
            try:
                account = self._import_account(item)
                if account:
                    stats['success'] += 1
                    self.imported_accounts.append(account)
                else:
                    stats['skipped'] += 1
            except Exception:
                logger.exception("Account import row failed")
                self.errors.append("Account import failed")
                stats['failed'] += 1

        self.db.commit()
        return stats


class CsvImportService(ImportService):
    """CSV import service"""

    def parse_csv(self, content: str, delimiter: str = ',') -> List[Dict[str, Any]]:
        """Parse CSV content into list of dictionaries"""
        reader = csv.DictReader(content.splitlines(), delimiter=delimiter)
        return list(reader)

    def _import_account(self, data: Dict[str, str]) -> Optional[Account]:
        """Import a single account from CSV row"""
        # Map CSV columns to account fields
        name = data.get('name') or data.get('title') or data.get('account') or ''
        if not name:
            self.errors.append("Account name is required")
            return None

        # Get or create category
        category = None
        if data.get('category'):
            category = self._get_or_create_category(data['category'])

        # Get or create client
        client = None
        if data.get('client'):
            client = self._get_or_create_client(
                data['client'],
                contact=data.get('contact') or '',
                notes=data.get('client_notes') or ''
            )

        # Encrypt password
        password = data.get('password', '')
        encrypted_pass, key = self._encrypt_password(password)

        # Create account
        account = Account(
            userGroupId=self._user_group_id(),
            userId=self.user_id,
            userEditId=self.user_id,
            clientId=client.id if client else None,
            name=name,
            categoryId=category.id if category else None,
            login=data.get('login') or data.get('username'),
            url=data.get('url') or data.get('website'),
            pass_=encrypted_pass,
            key=key,
            notes=data.get('notes') or data.get('description'),
            passDateChange=int(data['passDateChange']) if data.get('passDateChange') else None
        )

        self.db.add(account)
        self.db.flush()

        # Import tags
        if data.get('tags'):
            tag_names = [t.strip() for t in data['tags'].split(',')]
            for tag_name in tag_names:
                if tag_name:
                    tag = self._get_or_create_tag(tag_name)
                    account_tag = AccountToTag(accountId=account.id, tagId=tag.id)
                    self.db.add(account_tag)

        return account


class XmlImportService(ImportService):
    """Import native sysPass XML, including password-protected exports."""

    def __init__(
        self,
        db: Session,
        encryption_service: EncryptionService,
        user_id: int,
        export_password: Optional[str] = None,
        import_master_password: Optional[str] = None,
        current_master_password: Optional[str] = None,
    ):
        super().__init__(db, encryption_service, user_id)
        self.export_password = export_password or ""
        self.import_master_password = import_master_password or ""
        self.current_master_password = current_master_password or ""

    def _expand_encrypted_sections(self, root) -> None:
        encrypted = root.find("Encrypted")
        if encrypted is None:
            return
        if not self.export_password:
            raise ValueError("Encrypted sysPass XML requires an export password")

        for data_node in encrypted.findall("Data"):
            encoded = (data_node.text or "").strip()
            ciphertext_hex = base64.b64decode(encoded).decode("ascii")
            section_xml = decrypt_with_password(
                ciphertext_hex,
                data_node.get("key", ""),
                self.export_password,
            )
            root.append(parse_xml_safely(section_xml))
        root.remove(encrypted)

    def parse_xml(self, content: str) -> List[Dict[str, Any]]:
        """Parse XML content into list of account dictionaries"""
        root = parse_xml_safely(content)
        self._expand_encrypted_sections(root)

        if root.tag == "Root" and (root.findtext("./Meta/Generator") or "").lower() == "syspass":
            return self._parse_native_xml(root)

        accounts = []

        for account_elem in root.findall('.//account'):
            account_data = {}

            # Basic fields
            for field in ['name', 'login', 'url', 'pass', 'notes', 'category', 'client']:
                elem = account_elem.find(field)
                if elem is not None and elem.text:
                    account_data[field] = elem.text

            # Additional fields
            for field in ['passDateChange', 'countView', 'countDecrypt']:
                elem = account_elem.find(field)
                if elem is not None and elem.text:
                    account_data[field] = elem.text

            # Tags
            tags_elem = account_elem.find('tags')
            if tags_elem is not None:
                account_data['tags'] = ','.join([t.text for t in tags_elem.findall('tag') if t.text])

            accounts.append(account_data)

        return accounts

    def _parse_native_xml(self, root) -> List[Dict[str, Any]]:
        categories = {
            node.get("id"): node.findtext("name", "")
            for node in root.findall("./Categories/Category")
        }
        clients = {
            node.get("id"): node.findtext("name", "")
            for node in root.findall("./Clients/Client")
        }
        tags = {
            node.get("id"): node.findtext("name", "")
            for node in root.findall("./Tags/Tag")
        }

        accounts = []
        for node in root.findall("./Accounts/Account"):
            account = {
                "_native_ciphertext": True,
                "name": node.findtext("name", ""),
                "login": node.findtext("login"),
                "url": node.findtext("url"),
                "notes": node.findtext("notes"),
                "pass": node.findtext("pass", ""),
                "key": node.findtext("key", ""),
                "category": categories.get(node.findtext("categoryId"), ""),
                "client": clients.get(node.findtext("clientId"), ""),
            }
            account["tags"] = ",".join(
                tags.get(tag.get("id"), "")
                for tag in node.findall("./tags/tag")
                if tags.get(tag.get("id"), "")
            )
            accounts.append(account)
        return accounts

    def _import_account(self, data: Dict[str, str]) -> Optional[Account]:
        """Import account from XML data"""
        name = data.get('name')
        if not name:
            self.errors.append("Account name is required")
            return None

        # Get or create category
        category = None
        if data.get('category'):
            category = self._get_or_create_category(data['category'])

        # Get or create client
        client = None
        if data.get('client'):
            client = self._get_or_create_client(data['client'])

        password = data.get('pass', '')
        if data.get("_native_ciphertext") and password and data.get("key"):
            encrypted_pass = password
            key = data["key"]
            if self.import_master_password:
                plaintext = decrypt_with_password(
                    encrypted_pass, key, self.import_master_password
                )
                target_master = self.current_master_password or self.import_master_password
                encrypted_pass, key = encrypt_account_pass(plaintext, target_master)
        elif password:
            encrypted_pass, key = self._encrypt_password(password)
        else:
            encrypted_pass, key = self._encrypt_password("")

        account = Account(
            userGroupId=self._user_group_id(),
            userId=self.user_id,
            userEditId=self.user_id,
            clientId=client.id if client else None,
            name=name,
            categoryId=category.id if category else None,
            login=data.get('login'),
            url=data.get('url'),
            pass_=encrypted_pass.encode() if isinstance(encrypted_pass, str) else encrypted_pass,
            key=key.encode() if isinstance(key, str) else key,
            notes=data.get('notes'),
            passDateChange=int(data['passDateChange']) if data.get('passDateChange') else None,
            countView=int(data['countView']) if data.get('countView') else 0,
            countDecrypt=int(data['countDecrypt']) if data.get('countDecrypt') else 0
        )

        self.db.add(account)
        self.db.flush()

        # Import tags
        if data.get('tags'):
            tag_names = [t.strip() for t in data['tags'].split(',')]
            for tag_name in tag_names:
                if tag_name:
                    tag = self._get_or_create_tag(tag_name)
                    account_tag = AccountToTag(accountId=account.id, tagId=tag.id)
                    self.db.add(account_tag)

        return account


class KeePassImportService(ImportService):
    """KeePass XML import service"""

    def parse_keepass(self, content: str) -> List[Dict[str, Any]]:
        """Parse KeePass 2.x XML, preserving its group hierarchy as categories."""
        root = parse_xml_safely(content)
        if root.tag != "KeePassFile":
            raise ValueError("File is not KeePass 2.x XML")
        root_group = root.find("./Root/Group")
        if root_group is None:
            raise ValueError("KeePass XML is missing its root group")

        accounts: List[Dict[str, Any]] = []

        def walk_group(group, category: Optional[str] = None) -> None:
            for entry in group.findall("Entry"):
                fields = {
                    item.findtext("Key", "").casefold(): item.findtext("Value", "")
                    for item in entry.findall("String")
                    if item.findtext("Key")
                }
                name = fields.get("title", "")
                if not name:
                    continue
                tags = (entry.findtext("Tags") or "").replace(";", ",")
                account_data = {
                    "name": name,
                    "login": fields.get("username"),
                    "pass": fields.get("password", ""),
                    "url": fields.get("url"),
                    "notes": fields.get("notes") or fields.get("comments"),
                    "client": fields.get("client"),
                    "tags": tags,
                }
                if category:
                    account_data["category"] = category
                accounts.append(account_data)

            for child in group.findall("Group"):
                child_name = child.findtext("Name") or category
                walk_group(child, child_name)

        # Entries directly inside the database root are uncategorized. Nested
        # KeePass groups map to sysPass categories using the nearest group name.
        walk_group(root_group)
        return accounts

    def _import_account(self, data: Dict[str, str]) -> Optional[Account]:
        """Import account from KeePass data"""
        name = data.get('name')
        if not name:
            self.errors.append("Account name is required")
            return None

        # Get or create category from KeePass group
        category = None
        if data.get('category'):
            category = self._get_or_create_category(data['category'])

        client = None
        if data.get('client'):
            client = self._get_or_create_client(data['client'])

        # Encrypt password
        password = data.get('pass', '')
        encrypted_pass, key = self._encrypt_password(password)

        account = Account(
            userGroupId=self._user_group_id(),
            userId=self.user_id,
            userEditId=self.user_id,
            clientId=client.id if client else None,
            name=name,
            categoryId=category.id if category else None,
            login=data.get('login'),
            url=data.get('url'),
            pass_=encrypted_pass,
            key=key,
            notes=data.get('notes')
        )

        self.db.add(account)
        self.db.flush()

        tag_names = (value.strip() for value in data.get('tags', '').split(','))
        for tag_name in filter(None, tag_names):
            tag = self._get_or_create_tag(tag_name)
            self.db.add(AccountToTag(accountId=account.id, tagId=tag.id))

        return account


class ExportService:
    """Export accounts to various formats"""

    def __init__(self, db: Session, encryption_service: EncryptionService):
        self.db = db
        self.encryption = encryption_service

    def _decrypt_for_export(
        self, account: Account, master_password: Optional[str] = None
    ) -> str:
        if not account.pass_:
            return ""
        pass_text = (
            account.pass_.decode("ascii")
            if isinstance(account.pass_, bytes)
            else str(account.pass_)
        )
        key_text = (
            account.key.decode("ascii")
            if isinstance(account.key, bytes)
            else str(account.key or "")
        )
        if key_text.startswith("def10000"):
            if not master_password:
                raise ValueError(
                    "The vault master password is required to export PHP-encrypted accounts"
                )
            return decrypt_account_pass(pass_text, key_text, master_password)
        return self.encryption.decrypt(pass_text)

    def export_to_csv(self, account_ids: List[int] = None) -> str:
        """Export accounts to CSV format"""
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'name', 'login', 'url', 'password', 'notes',
            'category', 'client', 'tags', 'passDateChange'
        ])

        # Query accounts
        query = select(Account)
        if account_ids is not None:
            query = query.where(Account.id.in_(account_ids))

        accounts = self.db.execute(query).scalars().all()

        for account in accounts:
            # Get category name
            category_name = ''
            if account.categoryId:
                category = self.db.get(Category, account.categoryId)
                category_name = category.name if category else ''

            # Get client name
            client_name = ''
            if account.clientId:
                client = self.db.get(Client, account.clientId)
                client_name = client.name if client else ''

            # Get tags
            tags = []
            for account_tag in account.tags:
                tag = self.db.get(Tag, account_tag.tagId)
                if tag:
                    tags.append(tag.name)

            # Decrypt password for export
            password = ''  # nosec B105
            if account.pass_:
                try:
                    password = self._decrypt_for_export(account)
                except Exception:
                    password = '[encrypted]'  # nosec B105

            writer.writerow([
                account.name,
                account.login or '',
                account.url or '',
                password,
                account.notes or '',
                category_name,
                client_name,
                ','.join(tags),
                account.passDateChange or ''
            ])

        return output.getvalue()

    @staticmethod
    def _php_xml_fragment(node) -> str:
        return ET.tostring(node, encoding="unicode", short_empty_elements=True).replace(" />", "/>")

    @staticmethod
    def _append_text(parent, name: str, value: Any) -> None:
        child = ET.SubElement(parent, name)
        child.text = "" if value is None else str(value)

    def _native_account_credentials(
        self, account: Account, master_password: Optional[str]
    ) -> tuple[str, str]:
        pass_text = account.pass_.decode("ascii") if isinstance(account.pass_, bytes) else str(account.pass_ or "")
        key_text = account.key.decode("ascii") if isinstance(account.key, bytes) else str(account.key or "")
        if key_text.startswith("def10000"):
            return pass_text, key_text
        if not master_password:
            raise ValueError(
                "A master password is required to convert Python-encrypted accounts to native sysPass XML"
            )
        plaintext = self.encryption.decrypt(pass_text)
        return encrypt_account_pass(plaintext, master_password)

    def export_to_xml(
        self,
        account_ids: List[int] = None,
        export_password: Optional[str] = None,
        master_password: Optional[str] = None,
        username: str = "pySysPass",
        user_id: int = 0,
        group_id: int = 0,
        group_name: str = "",
    ) -> str:
        """Export PHP-native sysPass XML with optional outer encryption."""
        root = ET.Element("Root")
        meta = ET.SubElement(root, "Meta")
        self._append_text(meta, "Generator", "sysPass")
        self._append_text(meta, "Version", "3211.22070201")
        self._append_text(meta, "Time", int(time.time()))
        user_node = ET.SubElement(meta, "User", {"id": str(user_id)})
        user_node.text = username
        group_node = ET.SubElement(meta, "Group", {"id": str(group_id)})
        group_node.text = group_name

        query = select(Account)
        if account_ids is not None:
            query = query.where(Account.id.in_(account_ids))
        accounts = self.db.execute(query).scalars().all()

        category_ids = sorted({account.categoryId for account in accounts if account.categoryId})
        client_ids = sorted({account.clientId for account in accounts if account.clientId})
        tag_ids = sorted({item.tagId for account in accounts for item in account.tags})

        categories_node = ET.Element("Categories")
        for category_id in category_ids:
            category = self.db.get(Category, category_id)
            if category:
                node = ET.SubElement(categories_node, "Category", {"id": str(category.id)})
                self._append_text(node, "name", category.name)
                self._append_text(node, "description", category.description)

        clients_node = ET.Element("Clients")
        for client_id in client_ids:
            client = self.db.get(Client, client_id)
            if client:
                node = ET.SubElement(clients_node, "Client", {"id": str(client.id)})
                self._append_text(node, "name", client.name)
                self._append_text(node, "description", client.description)

        tags_node = ET.Element("Tags")
        for tag_id in tag_ids:
            tag = self.db.get(Tag, tag_id)
            if tag:
                node = ET.SubElement(tags_node, "Tag", {"id": str(tag.id)})
                self._append_text(node, "name", tag.name)

        accounts_node = ET.Element("Accounts")
        for account in accounts:
            pass_text, key_text = self._native_account_credentials(account, master_password)
            node = ET.SubElement(accounts_node, "Account", {"id": str(account.id)})
            for name, value in (
                ("name", account.name),
                ("clientId", account.clientId),
                ("categoryId", account.categoryId),
                ("login", account.login),
                ("url", account.url),
                ("notes", account.notes),
                ("pass", pass_text),
                ("key", key_text),
            ):
                self._append_text(node, name, value)
            account_tags = ET.SubElement(node, "tags")
            for account_tag in account.tags:
                ET.SubElement(account_tags, "tag", {"id": str(account_tag.tagId)})

        sections = [categories_node, clients_node, tags_node, accounts_node]
        if export_password:
            password_hash = get_password_hash(export_password)
            if isinstance(password_hash, bytes):
                password_hash = password_hash.decode("ascii")
            encrypted_node = ET.SubElement(
                root, "Encrypted", {"hash": password_hash.replace("$2b$", "$2y$", 1)}
            )
            for section in sections:
                ciphertext_hex, key_hex = encrypt_with_password(
                    self._php_xml_fragment(section), export_password
                )
                data_node = ET.SubElement(encrypted_node, "Data", {"key": key_hex})
                data_node.text = base64.b64encode(ciphertext_hex.encode("ascii")).decode("ascii")
        else:
            root.extend(sections)

        hash_input = "".join(self._php_xml_fragment(node) for node in list(root) if node.tag != "Meta")
        # PHP's native XML format mandates these SHA-1 values. Integrity is
        # separately authenticated by the HMAC-SHA-256 signature below.
        digest = hashlib.sha1(hash_input.encode("utf-8")).hexdigest()  # lgtm[py/weak-sensitive-data-hashing]
        signing_key = export_password or hashlib.sha1(
            get_password_salt().encode("utf-8")
        ).hexdigest()  # lgtm[py/weak-sensitive-data-hashing]
        signature = hmac.new(
            signing_key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256
        ).hexdigest()
        hash_node = ET.SubElement(meta, "Hash", {"sign": signature})
        hash_node.text = digest

        body = self._php_xml_fragment(root)
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + body

    def export_to_keepass(
        self,
        account_ids: List[int] = None,
        master_password: Optional[str] = None,
    ) -> str:
        """Export plaintext KeePass 2.x interchange XML."""
        root = ET.Element("KeePassFile")
        meta = ET.SubElement(root, "Meta")
        self._append_text(meta, "Generator", "pySysPass")
        self._append_text(meta, "DatabaseName", "pySysPass Export")
        self._append_text(
            meta,
            "DatabaseDescription",
            "Accounts exported from pySysPass",
        )
        memory = ET.SubElement(meta, "MemoryProtection")
        for field, value in (
            ("ProtectTitle", "False"),
            ("ProtectUserName", "False"),
            ("ProtectPassword", "True"),
            ("ProtectURL", "False"),
            ("ProtectNotes", "False"),
        ):
            self._append_text(memory, field, value)
        ET.SubElement(meta, "Binaries")
        ET.SubElement(meta, "CustomData")

        root_node = ET.SubElement(root, "Root")
        root_group = ET.SubElement(root_node, "Group")
        self._append_text(root_group, "UUID", self._keepass_uuid())
        self._append_text(root_group, "Name", "pySysPass")
        self._append_text(root_group, "Notes", "Imported from pySysPass")
        self._append_text(root_group, "IconID", 48)
        self._append_keepass_times(root_group)
        self._append_text(root_group, "IsExpanded", "True")

        # Query accounts
        query = select(Account)
        if account_ids is not None:
            query = query.where(Account.id.in_(account_ids))

        accounts = self.db.execute(query).scalars().all()

        category_groups = {}

        def group_for(account: Account):
            if not account.categoryId:
                return root_group
            category = self.db.get(Category, account.categoryId)
            if not category:
                return root_group
            if category.id not in category_groups:
                group = ET.SubElement(root_group, "Group")
                self._append_text(group, "UUID", self._keepass_uuid())
                self._append_text(group, "Name", category.name)
                self._append_text(group, "Notes", category.description)
                self._append_text(group, "IconID", 48)
                self._append_keepass_times(group)
                self._append_text(group, "IsExpanded", "True")
                category_groups[category.id] = group
            return category_groups[category.id]

        def add_string(entry, key: str, value: Any, protect: bool = False):
            string_elem = ET.SubElement(entry, "String")
            self._append_text(string_elem, "Key", key)
            value_elem = ET.SubElement(string_elem, "Value")
            if protect:
                value_elem.set("ProtectInMemory", "True")
            value_elem.text = "" if value is None else str(value)

        for account in accounts:
            entry = ET.SubElement(group_for(account), "Entry")
            self._append_text(entry, "UUID", self._keepass_uuid())
            self._append_text(entry, "IconID", 0)
            self._append_text(entry, "ForegroundColor", "")
            self._append_text(entry, "BackgroundColor", "")
            self._append_text(entry, "OverrideURL", "")

            tags = []
            for account_tag in account.tags:
                tag = self.db.get(Tag, account_tag.tagId)
                if tag:
                    tags.append(tag.name)
            self._append_text(entry, "Tags", ";".join(tags))
            self._append_keepass_times(entry, account.dateAdd, account.dateEdit)

            add_string(entry, "Title", account.name)
            add_string(entry, "UserName", account.login)
            add_string(
                entry,
                "Password",
                self._decrypt_for_export(account, master_password),
                protect=True,
            )
            add_string(entry, "URL", account.url)
            add_string(entry, "Notes", account.notes)
            if account.clientId:
                client = self.db.get(Client, account.clientId)
                if client:
                    add_string(entry, "Client", client.name)

            auto_type = ET.SubElement(entry, "AutoType")
            self._append_text(auto_type, "Enabled", "True")
            self._append_text(auto_type, "DataTransferObfuscation", 0)
            ET.SubElement(entry, "History")

        return ET.tostring(root, encoding='utf-8', xml_declaration=True).decode('utf-8')

    def export_to_kdbx(
        self,
        export_password: str,
        account_ids: List[int] = None,
        master_password: Optional[str] = None,
    ) -> bytes:
        """Create a password-protected KDBX 4 database."""
        if not export_password:
            raise ValueError("An export password is required")

        from pykeepass import create_database

        query = select(Account)
        if account_ids is not None:
            query = query.where(Account.id.in_(account_ids))
        accounts = self.db.execute(query).scalars().all()

        with tempfile.TemporaryDirectory(prefix="pysyspass-kdbx-") as directory:
            output_path = Path(directory) / "pysyspass_export.kdbx"
            database = create_database(str(output_path), password=export_password)
            database.root_group.name = "pySysPass"
            database.root_group.notes = "Accounts exported from pySysPass"
            category_groups = {}

            for account in accounts:
                destination = database.root_group
                if account.categoryId:
                    category = self.db.get(Category, account.categoryId)
                    if category:
                        destination = category_groups.get(category.id)
                        if destination is None:
                            destination = database.add_group(
                                database.root_group,
                                category.name,
                                notes=category.description or "",
                            )
                            category_groups[category.id] = destination

                tags = []
                for account_tag in account.tags:
                    tag = self.db.get(Tag, account_tag.tagId)
                    if tag:
                        tags.append(tag.name)

                entry = database.add_entry(
                    destination,
                    account.name or "",
                    account.login or "",
                    self._decrypt_for_export(account, master_password),
                    url=account.url or "",
                    notes=account.notes or "",
                    tags=tags,
                )
                if account.clientId:
                    client = self.db.get(Client, account.clientId)
                    if client:
                        entry.set_custom_property("Client", client.name)

            database.save()
            return output_path.read_bytes()

    @staticmethod
    def _keepass_uuid() -> str:
        return base64.b64encode(uuid.uuid4().bytes).decode("ascii")

    def _append_keepass_times(
        self,
        parent,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
    ) -> None:
        now = datetime.now(UTC)

        def keepass_time(value: Optional[datetime]) -> str:
            value = value or now
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        created_at = keepass_time(created)
        modified_at = keepass_time(modified or created)
        times = ET.SubElement(parent, "Times")
        for name, value in (
            ("CreationTime", created_at),
            ("LastModificationTime", modified_at),
            ("LastAccessTime", modified_at),
            ("ExpiryTime", modified_at),
            ("Expires", "False"),
            ("UsageCount", 0),
            ("LocationChanged", modified_at),
        ):
            self._append_text(times, name, value)
