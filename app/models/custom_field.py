"""Custom field models matching the live PHP sysPass schema."""
from sqlalchemy import Column, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import relationship

from app.db.base import Base, FlexibleBinary, mysql_integer, mysql_smallint, mysql_tinyint


class CustomFieldType(Base):
    __tablename__ = "CustomFieldType"
    __table_args__ = (UniqueConstraint("name", name="uk_CustomFieldType_01"),)

    id   = Column(mysql_tinyint(width=3), primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    text = Column(String(50), nullable=False)

    # -- Python-only helpers -------------------------------------------------
    @property
    def type(self):  return self.name
    @type.setter
    def type(self, value): self.name = value
    @property
    def icon(self): return self.name
    @property
    def is_encrypted(self): return self.name == "password"
    @property
    def isEncrypted(self):  return self.is_encrypted
    @property
    def is_active(self): return True

    definitions = relationship("CustomFieldDef", back_populates="fieldType")


class CustomFieldDef(Base):
    __tablename__ = "CustomFieldDefinition"
    __table_args__ = (Index('fk_CustomFieldDefinition_typeId', 'typeId'),)

    id         = Column(mysql_integer(), primary_key=True, autoincrement=True)
    name       = Column(String(100), nullable=False)
    moduleId   = Column(mysql_smallint(), nullable=False)
    required   = Column(mysql_tinyint(), nullable=True)
    help       = Column(String(255), nullable=True)
    showInList = Column(mysql_tinyint(), nullable=True)
    typeId     = Column(mysql_tinyint(width=3), ForeignKey("CustomFieldType.id", name='fk_CustomFieldDefinition_typeId',
                        onupdate='CASCADE'), nullable=False)
    isEncrypted = Column(mysql_tinyint(), default=1, server_default=text("1"), nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def type_id(self): return self.typeId
    @property
    def description(self): return self.help
    @description.setter
    def description(self, value): self.help = value
    @property
    def size(self): return 50
    @property
    def is_required(self): return bool(self.required)
    @is_required.setter
    def is_required(self, value): self.required = int(value)
    @property
    def is_show(self): return bool(self.showInList)
    @is_show.setter
    def is_show(self, value): self.showInList = int(value)
    @property
    def order_num(self): return self.id
    @property
    def default_val(self): return None

    fieldType = relationship("CustomFieldType", back_populates="definitions")
    values    = relationship("CustomFieldValue", back_populates="definition")


class CustomFieldValue(Base):
    __tablename__ = "CustomFieldData"
    __table_args__ = (
        Index('idx_CustomFieldData_01', 'definitionId'),
        Index('idx_CustomFieldData_02', 'itemId', 'moduleId'),
        Index('idx_CustomFieldData_03', 'moduleId'),
        # uk_CustomFieldData_01 is a regular KEY in DB, not UNIQUE
        Index('uk_CustomFieldData_01', 'moduleId', 'itemId', 'definitionId'),
    )

    id           = Column(mysql_integer(), primary_key=True, autoincrement=True)
    moduleId     = Column(mysql_smallint(), nullable=False)
    itemId       = Column(mysql_integer(), nullable=False)
    definitionId = Column(mysql_integer(), ForeignKey("CustomFieldDefinition.id", name='fk_CustomFieldData_definitionId'), nullable=False)
    data         = Column(FlexibleBinary(mysql_type=mysql.LONGBLOB()), nullable=True)
    key          = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def defId(self): return self.definitionId
    @defId.setter
    def defId(self, value): self.definitionId = value

    @property
    def accountId(self): return self.itemId
    @accountId.setter
    def accountId(self, value): self.itemId = value

    @property
    def value(self):
        if self.data is None:
            return None
        if isinstance(self.data, bytes):
            return self.data.decode("utf-8", errors="replace")
        return self.data

    @value.setter
    def value(self, value):
        self.data = value.encode("utf-8") if isinstance(value, str) else value

    @property
    def valueEncrypted(self): return self.data if self.key else None
    @valueEncrypted.setter
    def valueEncrypted(self, value): self.data = value

    definition = relationship("CustomFieldDef", back_populates="values")
