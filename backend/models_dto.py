from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import date, datetime
import re
from pydantic import BaseModel, field_validator

class SearchByNikRequest(BaseModel):
    nik: str = Field(..., description="14 digit NIK pencarian")

    @field_validator("nik")
    @classmethod
    def validate_nik_format(cls, v: str) -> str:
        clean_nik = v.strip()
        if not re.fullmatch(r"^\d{14}$", clean_nik):
            raise ValueError("Format NIK tidak valid. NIK wajib berupa 14 digit angka.")
        return clean_nik

class AnggotaPublicResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nama_lengkap: str
    jenis_kelamin: str
    tempat_lahir: Optional[str] = None
    tanggal_lahir: Optional[date] = None
    pekerjaan_terakhir: Optional[str] = None
    ruangan: Optional[str] = None
    nama_bank: Optional[str] = None
    kode_bank: Optional[str] = None
    nama_kppn: Optional[str] = None


class AnggotaMaskedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nama_lengkap: str
    jenis_kelamin: str
    ruangan: Optional[str] = None
    
    no_ktp_masked: str = Field(..., description="Contoh: 3174********1234")
    email_masked: Optional[str] = Field(None, description="Contoh: on***@example.com")
    handphone_masked: Optional[str] = Field(None, description="Contoh: 0812****7890")
    rekening_masked: Optional[str] = Field(None, description="Contoh: ************4567")
    agama_masked: str = "TERLINDUNGI"
    
    nama_bank: Optional[str] = None
    nama_kppn: Optional[str] = None


class AnggotaFullSensitiveResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nama_lengkap: str
    jenis_kelamin: str
    tempat_lahir: Optional[str] = None
    tanggal_lahir: Optional[date] = None
    pekerjaan_terakhir: Optional[str] = None
    ruangan: Optional[str] = None
    
    no_ktp: str
    npwp: Optional[str] = None
    rekening: Optional[str] = None
    nama_rekening: Optional[str] = None
    nip_kppn: Optional[str] = None
    handphone: Optional[str] = None
    email: Optional[str] = None
    agama: Optional[str] = None
    alamat_jakarta: Optional[str] = None
    alamat_daerah: Optional[str] = None
    
    nama_bank: Optional[str] = None
    kode_bank: Optional[str] = None
    nama_kppn: Optional[str] = None
    key_version: int



class SearchByEmailRequest(BaseModel):
    email: str = Field(..., description="Alamat email pencarian")


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: str
    role: str
    action: str
    target_anggota_id: Optional[int] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    accessed_at: datetime