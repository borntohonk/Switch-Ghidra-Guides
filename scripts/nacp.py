# Copyright (c) 2026 borntohonk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
NACP (Nintendo Application Control Properties) Parser
Fully compliant with https://switchbrew.org/wiki/NACP specification

This module parses NACP (Application Control Properties) files from Nintendo Switch games.
A NACP is typically found within the RomFS section of a Control NCA (ContentType=3).

Two title-data formats are supported:
  Format0 (TitlesDataFormat=0): Classic uncompressed layout.
      Bytes 0x0000–0x2FFF hold 16 ApplicationTitle entries (0x300 each).
  Format1 (TitlesDataFormat=1): Compressed layout introduced in firmware ~21.0.
      Bytes 0x0000–0x0001 = little-endian u16 compressed size N.
      Bytes 0x0002–(0x0002+N-1) = raw-deflate (zlib wbits=-15) stream.
      Decompresses to 0x6000 bytes → 32 ApplicationTitle slots (0x300 each).
      The rest of the NACP structure (everything from 0x3000 onward) is
      unchanged regardless of format.
"""

import struct
import zlib
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional


# ============================================================================
# Language and Enum Constants
# ============================================================================

class LanguageCode(IntEnum):
    """NACP language codes per Settings services specification"""
    AMERICAN_ENGLISH = 0
    BRITISH_ENGLISH = 1
    JAPANESE = 2
    FRENCH = 3
    GERMAN = 4
    LATIN_AMERICAN_SPANISH = 5
    SPANISH = 6
    ITALIAN = 7
    DUTCH = 8
    CANADIAN_FRENCH = 9
    PORTUGUESE = 10
    RUSSIAN = 11
    KOREAN = 12
    TRADITIONAL_CHINESE = 13
    SIMPLIFIED_CHINESE = 14
    BRAZILIAN_PORTUGUESE = 15  # v10.1.0+
    POLISH = 16                # v21.0.0+
    THAI = 17                  # v21.0.0+


LANGUAGE_NAMES = {
    LanguageCode.AMERICAN_ENGLISH:    "American English",
    LanguageCode.BRITISH_ENGLISH:     "British English",
    LanguageCode.JAPANESE:            "Japanese",
    LanguageCode.FRENCH:              "French",
    LanguageCode.GERMAN:              "German",
    LanguageCode.LATIN_AMERICAN_SPANISH: "Latin American Spanish",
    LanguageCode.SPANISH:             "Spanish",
    LanguageCode.ITALIAN:             "Italian",
    LanguageCode.DUTCH:               "Dutch",
    LanguageCode.CANADIAN_FRENCH:     "Canadian French",
    LanguageCode.PORTUGUESE:          "Portuguese",
    LanguageCode.RUSSIAN:             "Russian",
    LanguageCode.KOREAN:              "Korean",
    LanguageCode.TRADITIONAL_CHINESE: "Traditional Chinese",
    LanguageCode.SIMPLIFIED_CHINESE:  "Simplified Chinese",
    LanguageCode.BRAZILIAN_PORTUGUESE:"Brazilian Portuguese",
    LanguageCode.POLISH:              "Polish",
    LanguageCode.THAI:                "Thai",
}

# Maximum language slots for each format
FORMAT0_LANGUAGE_COUNT = 16
FORMAT1_LANGUAGE_COUNT = 32

# Decompressed size for Format1 title data
FORMAT1_DECOMPRESSED_SIZE = 0x6000  # 32 * 0x300


class StartupUserAccount(IntEnum):
    NONE = 0
    REQUIRED = 1
    REQUIRED_WITH_NETWORK_SERVICE_ACCOUNT_AVAILABLE = 2


class UserAccountSwitchLock(IntEnum):
    DISABLE = 0
    ENABLE = 1


class AddOnContentRegistrationType(IntEnum):
    ALL_ON_LAUNCH = 0
    ON_DEMAND = 1


class Screenshot(IntEnum):
    ALLOW = 0
    DENY = 1


class VideoCapture(IntEnum):
    DISABLE = 0
    MANUAL = 1
    ENABLE = 2


class DataLossConfirmation(IntEnum):
    NONE = 0
    REQUIRED = 1


class PlayLogPolicy(IntEnum):
    OPEN = 0
    LOG_ONLY = 1
    NONE = 2
    CLOSED = 3


class LogoType(IntEnum):
    LICENSED_BY_NINTENDO = 0
    DISTRIBUTED_BY_NINTENDO = 1
    NINTENDO = 2


class LogoHandling(IntEnum):
    AUTO = 0
    MANUAL = 1


class RuntimeAddOnContentInstall(IntEnum):
    DENY = 0
    ALLOW_APPEND = 1
    ALLOW_APPEND_BUT_DONT_DOWNLOAD_WHEN_USING_NETWORK = 2


class RuntimeParameterDelivery(IntEnum):
    ALWAYS = 0
    ALWAYS_IF_USER_STATE_MATCHED = 1
    ON_RESTART = 2


class AppropriateAgeForChina(IntEnum):
    NONE = 0
    AGE_8 = 1
    AGE_12 = 2
    AGE_16 = 3


class CrashReport(IntEnum):
    DENY = 0
    ALLOW = 1


class Hdcp(IntEnum):
    NONE = 0
    REQUIRED = 1


class PlayLogQueryCapability(IntEnum):
    NONE = 0
    WHITE_LIST = 1
    ALL = 2


class OrganizationType(IntEnum):
    CERO = 0
    GRACGCRB = 1
    CLASSIND = 2
    USK = 3
    ESRB = 4
    RATING_AND_LABEL_ADMINISTRATION_ORGANIZATION = 5
    GENERIC = 6
    PEGI = 7
    PEGIPORTUGUESE = 8
    PIDVD = 9
    MOBAGEAGEREATING = 10
    MEDIA_TECHNOLOGY_TAINMENT_ASSOCIATION = 11
    COMPUTER_ENTERTAINMENT_RATING_ORGANIZATION = 12


class TitlesDataFormat(IntEnum):
    """Titles data format (v21.0.0+)"""
    FORMAT0 = 0  # Uncompressed array of 16 ApplicationTitle entries
    FORMAT1 = 1  # Raw-deflate compressed, decompresses to 32 ApplicationTitle entries


class ApparentPlatform(IntEnum):
    """Apparent platform (v20.0.0+)"""
    NX = 0
    SWITCH_2 = 1


# ============================================================================
# Structure Offsets and Sizes
# ============================================================================

NACP_TOTAL_SIZE = 0x4000

# Title section (first 0x3000 bytes in Format0; compressed blob in Format1)
NACP_TITLE_OFFSET = 0x0
NACP_TITLE_SIZE   = 0x3000   # used only in Format0

APPLICATION_TITLE_SIZE     = 0x300   # per language slot: 0x200 name + 0x100 publisher
APPLICATION_NAME_SIZE      = 0x200
APPLICATION_PUBLISHER_SIZE = 0x100

# Format1 compressed-blob layout (within the first 0x3000 bytes)
FORMAT1_COMPRESSED_SIZE_OFFSET = 0x0   # u16 LE: byte length of the deflate stream
FORMAT1_COMPRESSED_DATA_OFFSET = 0x2   # raw-deflate stream starts here

# Fixed-structure section starts at 0x3000 regardless of TitlesDataFormat
NACP_ISBN_OFFSET                        = 0x3000
NACP_ISBN_SIZE                          = 0x25
NACP_STARTUP_USER_ACCOUNT_OFFSET        = 0x3025
NACP_USER_ACCOUNT_SWITCH_LOCK_OFFSET    = 0x3026
NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_OFFSET = 0x3027
NACP_ATTRIBUTE_FLAG_OFFSET              = 0x3028
NACP_SUPPORTED_LANGUAGE_FLAG_OFFSET     = 0x302C
NACP_PARENTAL_CONTROL_FLAG_OFFSET       = 0x3030
NACP_SCREENSHOT_OFFSET                  = 0x3034
NACP_VIDEO_CAPTURE_OFFSET               = 0x3035
NACP_DATA_LOSS_CONFIRMATION_OFFSET      = 0x3036
NACP_PLAY_LOG_POLICY_OFFSET             = 0x3037
NACP_PRESENCE_GROUP_ID_OFFSET           = 0x3038
NACP_RATING_AGE_OFFSET                  = 0x3040
NACP_DISPLAY_VERSION_OFFSET             = 0x3060
NACP_ADD_ON_CONTENT_BASE_ID_OFFSET      = 0x3070
NACP_SAVE_DATA_OWNER_ID_OFFSET          = 0x3078
NACP_USER_ACCOUNT_SAVE_DATA_SIZE_OFFSET         = 0x3080
NACP_USER_ACCOUNT_SAVE_DATA_JOURNAL_SIZE_OFFSET = 0x3088
NACP_DEVICE_SAVE_DATA_SIZE_OFFSET               = 0x3090
NACP_DEVICE_SAVE_DATA_JOURNAL_SIZE_OFFSET       = 0x3098
NACP_BCAT_DELIVERY_CACHE_STORAGE_SIZE_OFFSET    = 0x30A0
NACP_APPLICATION_ERROR_CODE_CATEGORY_OFFSET     = 0x30A8
NACP_LOCAL_COMMUNICATION_ID_OFFSET              = 0x30B0
NACP_LOGO_TYPE_OFFSET                           = 0x30F0
NACP_LOGO_HANDLING_OFFSET                       = 0x30F1
NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_OFFSET      = 0x30F2
NACP_RUNTIME_PARAMETER_DELIVERY_OFFSET          = 0x30F3
NACP_APPROPRIATE_AGE_FOR_CHINA_OFFSET           = 0x30F4
NACP_CRASH_REPORT_OFFSET                        = 0x30F6
NACP_HDCP_OFFSET                                = 0x30F7
NACP_SEED_FOR_PSEUDO_DEVICE_ID_OFFSET           = 0x30F8
NACP_BCAT_PASSPHRASE_OFFSET                     = 0x3100
NACP_STARTUP_USER_ACCOUNT_OPTION_OFFSET         = 0x3141
NACP_USER_ACCOUNT_SAVE_DATA_SIZE_MAX_OFFSET             = 0x3148
NACP_USER_ACCOUNT_SAVE_DATA_JOURNAL_SIZE_MAX_OFFSET     = 0x3150
NACP_DEVICE_SAVE_DATA_SIZE_MAX_OFFSET                   = 0x3158
NACP_DEVICE_SAVE_DATA_JOURNAL_SIZE_MAX_OFFSET           = 0x3160
NACP_TEMPORARY_STORAGE_SIZE_OFFSET              = 0x3168
NACP_CACHE_STORAGE_SIZE_OFFSET                  = 0x3170
NACP_CACHE_STORAGE_JOURNAL_SIZE_OFFSET          = 0x3178
NACP_CACHE_STORAGE_DATA_AND_JOURNAL_SIZE_MAX_OFFSET = 0x3180
NACP_CACHE_STORAGE_INDEX_MAX_OFFSET             = 0x3188
NACP_RUNTIME_UPGRADE_OFFSET                     = 0x318B
NACP_SUPPORTING_LIMITED_APPLICATION_LICENSES_OFFSET = 0x318C
NACP_PLAY_LOG_QUERYABLE_APPLICATION_ID_OFFSET   = 0x3190
NACP_PLAY_LOG_QUERY_CAPABILITY_OFFSET           = 0x3210
NACP_REPAIR_FLAG_OFFSET                         = 0x3211
NACP_PROGRAM_INDEX_OFFSET                       = 0x3212
NACP_REQUIRED_NETWORK_SERVICE_LICENSE_ON_LAUNCH_FLAG_OFFSET = 0x3213
NACP_APPLICATION_ERROR_CODE_PREFIX_OFFSET       = 0x3214  # v20.0.0+
NACP_TITLES_DATA_FORMAT_OFFSET                  = 0x3215  # v21.0.0+
NACP_ACD_INDEX_OFFSET                           = 0x3216  # v20.0.0+
NACP_APPARENT_PLATFORM_OFFSET                   = 0x3217  # v20.0.0+


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ApplicationTitle:
    """Single language entry for application title and publisher"""
    language: int   # raw index (may exceed LanguageCode enum for future langs)
    name: str = ""
    publisher: str = ""

    def __repr__(self):
        return (f"ApplicationTitle(lang={LANGUAGE_NAMES.get(self.language, f'Lang{self.language}')}, "
                f"name={self.name[:30]}...)")


@dataclass
class RatingAge:
    """Rating age entry for a specific organization"""
    organization: OrganizationType
    age: int = 0

    def __repr__(self):
        org_name = OrganizationType(self.organization).name
        return f"RatingAge(org={org_name}, age={self.age})"


# ============================================================================
# Main NACP Parser
# ============================================================================

@dataclass
class NACP:
    """
    Main NACP parser class.

    Supports both TitlesDataFormat 0 (classic, 16 languages) and
    TitlesDataFormat 1 (compressed, 32 language slots).

    The format byte lives at offset 0x3215 (NACP_TITLES_DATA_FORMAT_OFFSET).
    For Format1, the first two bytes of the file are a u16 LE giving the
    compressed-data length N, followed by N bytes of raw-deflate (wbits=-15)
    which decompress to 0x6000 bytes (32 × 0x300 ApplicationTitle slots).
    """

    # Application titles by language index
    titles: List[ApplicationTitle] = field(default_factory=list)

    # Basic metadata
    isbn: str = ""
    startup_user_account: int = 0
    user_account_switch_lock: int = 0
    add_on_content_registration_type: int = 0
    attribute_flag: int = 0
    supported_language_flag: int = 0
    parental_control_flag: int = 0
    screenshot: int = 0
    video_capture: int = 0
    data_loss_confirmation: int = 0
    play_log_policy: int = 0
    presence_group_id: int = 0

    # Rating ages (12 organizations)
    rating_ages: List[RatingAge] = field(default_factory=list)

    # Display and content info
    display_version: str = ""
    add_on_content_base_id: int = 0
    save_data_owner_id: int = 0

    # Save data sizes
    user_account_save_data_size: int = 0
    user_account_save_data_journal_size: int = 0
    device_save_data_size: int = 0
    device_save_data_journal_size: int = 0
    bcat_delivery_cache_storage_size: int = 0
    application_error_code_category: str = ""
    local_communication_id: int = 0

    # Logo and branding
    logo_type: int = 0
    logo_handling: int = 0

    # Runtime settings
    runtime_add_on_content_install: int = 0
    runtime_parameter_delivery: int = 0
    appropriate_age_for_china: int = 0
    crash_report: int = 0
    hdcp: int = 0

    # Additional fields
    seed_for_pseudo_device_id: int = 0
    bcat_passphrase: str = ""
    startup_user_account_option: int = 0
    user_account_save_data_size_max: int = 0
    user_account_save_data_journal_size_max: int = 0
    device_save_data_size_max: int = 0
    device_save_data_journal_size_max: int = 0
    temporary_storage_size: int = 0
    cache_storage_size: int = 0
    cache_storage_journal_size: int = 0
    cache_storage_data_and_journal_size_max: int = 0
    cache_storage_index_max: int = 0
    runtime_upgrade: int = 0
    supporting_limited_application_licenses: int = 0
    play_log_queryable_application_id: int = 0
    play_log_query_capability: int = 0
    repair_flag: int = 0
    program_index: int = 0
    required_network_service_license_on_launch_flag: int = 0
    application_error_code_prefix: int = 0
    titles_data_format: int = 0
    acd_index: int = 0
    apparent_platform: int = 0

    # Raw binary data
    raw_binary: bytes = b""

    # -----------------------------------------------------------------------
    # Public parse entry-point
    # -----------------------------------------------------------------------

    def parse(self, data: bytes):
        """
        Parse NACP binary data.

        Args:
            data: Complete NACP binary data (0x4000 bytes)
        """
        if len(data) < NACP_TOTAL_SIZE:
            raise ValueError(f"NACP data too small: {len(data)} < {NACP_TOTAL_SIZE}")

        self.raw_binary = data

        # ── Read TitlesDataFormat first (offset 0x3215) ───────────────────
        # This byte tells us how to interpret the first 0x3000 bytes.
        self.titles_data_format = data[NACP_TITLES_DATA_FORMAT_OFFSET]

        # ── Parse title section ───────────────────────────────────────────
        if self.titles_data_format == TitlesDataFormat.FORMAT1:
            self._parse_titles_format1(data)
        else:
            # Format0 (or unknown → fall back to Format0)
            self._parse_titles_format0(data)

        # ── Parse ISBN ────────────────────────────────────────────────────
        self.isbn = self._read_null_terminated_string(
            data, NACP_ISBN_OFFSET, NACP_ISBN_SIZE
        )

        # ── Single-byte flags and enums ───────────────────────────────────
        self.startup_user_account          = data[NACP_STARTUP_USER_ACCOUNT_OFFSET]
        self.user_account_switch_lock      = data[NACP_USER_ACCOUNT_SWITCH_LOCK_OFFSET]
        self.add_on_content_registration_type = data[NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_OFFSET]
        self.screenshot                    = data[NACP_SCREENSHOT_OFFSET]
        self.video_capture                 = data[NACP_VIDEO_CAPTURE_OFFSET]
        self.data_loss_confirmation        = data[NACP_DATA_LOSS_CONFIRMATION_OFFSET]
        self.play_log_policy               = data[NACP_PLAY_LOG_POLICY_OFFSET]
        self.logo_type                     = data[NACP_LOGO_TYPE_OFFSET]
        self.logo_handling                 = data[NACP_LOGO_HANDLING_OFFSET]
        self.runtime_add_on_content_install = data[NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_OFFSET]
        self.runtime_parameter_delivery    = data[NACP_RUNTIME_PARAMETER_DELIVERY_OFFSET]
        self.appropriate_age_for_china     = data[NACP_APPROPRIATE_AGE_FOR_CHINA_OFFSET]
        self.crash_report                  = data[NACP_CRASH_REPORT_OFFSET]
        self.hdcp                          = data[NACP_HDCP_OFFSET]
        self.startup_user_account_option   = data[NACP_STARTUP_USER_ACCOUNT_OPTION_OFFSET]
        self.runtime_upgrade               = data[NACP_RUNTIME_UPGRADE_OFFSET]
        self.repair_flag                   = data[NACP_REPAIR_FLAG_OFFSET]
        self.program_index                 = data[NACP_PROGRAM_INDEX_OFFSET]
        self.required_network_service_license_on_launch_flag = data[
            NACP_REQUIRED_NETWORK_SERVICE_LICENSE_ON_LAUNCH_FLAG_OFFSET]
        self.application_error_code_prefix = data[NACP_APPLICATION_ERROR_CODE_PREFIX_OFFSET]
        self.acd_index                     = data[NACP_ACD_INDEX_OFFSET]
        self.apparent_platform             = data[NACP_APPARENT_PLATFORM_OFFSET]
        self.play_log_query_capability     = data[NACP_PLAY_LOG_QUERY_CAPABILITY_OFFSET]

        # ── 4-byte flag fields ────────────────────────────────────────────
        self.attribute_flag = struct.unpack_from("<I", data, NACP_ATTRIBUTE_FLAG_OFFSET)[0]
        self.supported_language_flag = struct.unpack_from("<I", data, NACP_SUPPORTED_LANGUAGE_FLAG_OFFSET)[0]
        self.parental_control_flag   = struct.unpack_from("<I", data, NACP_PARENTAL_CONTROL_FLAG_OFFSET)[0]
        self.supporting_limited_application_licenses = struct.unpack_from(
            "<I", data, NACP_SUPPORTING_LIMITED_APPLICATION_LICENSES_OFFSET)[0]

        # ── 8-byte fields ─────────────────────────────────────────────────
        self.presence_group_id             = struct.unpack_from("<Q", data, NACP_PRESENCE_GROUP_ID_OFFSET)[0]
        self.add_on_content_base_id        = struct.unpack_from("<Q", data, NACP_ADD_ON_CONTENT_BASE_ID_OFFSET)[0]
        self.save_data_owner_id            = struct.unpack_from("<Q", data, NACP_SAVE_DATA_OWNER_ID_OFFSET)[0]
        self.user_account_save_data_size   = struct.unpack_from("<Q", data, NACP_USER_ACCOUNT_SAVE_DATA_SIZE_OFFSET)[0]
        self.user_account_save_data_journal_size = struct.unpack_from(
            "<Q", data, NACP_USER_ACCOUNT_SAVE_DATA_JOURNAL_SIZE_OFFSET)[0]
        self.device_save_data_size         = struct.unpack_from("<Q", data, NACP_DEVICE_SAVE_DATA_SIZE_OFFSET)[0]
        self.device_save_data_journal_size = struct.unpack_from("<Q", data, NACP_DEVICE_SAVE_DATA_JOURNAL_SIZE_OFFSET)[0]
        self.bcat_delivery_cache_storage_size = struct.unpack_from(
            "<Q", data, NACP_BCAT_DELIVERY_CACHE_STORAGE_SIZE_OFFSET)[0]
        self.local_communication_id        = struct.unpack_from("<Q", data, NACP_LOCAL_COMMUNICATION_ID_OFFSET)[0]
        self.seed_for_pseudo_device_id     = struct.unpack_from("<Q", data, NACP_SEED_FOR_PSEUDO_DEVICE_ID_OFFSET)[0]
        self.user_account_save_data_size_max = struct.unpack_from(
            "<Q", data, NACP_USER_ACCOUNT_SAVE_DATA_SIZE_MAX_OFFSET)[0]
        self.user_account_save_data_journal_size_max = struct.unpack_from(
            "<Q", data, NACP_USER_ACCOUNT_SAVE_DATA_JOURNAL_SIZE_MAX_OFFSET)[0]
        self.device_save_data_size_max     = struct.unpack_from("<Q", data, NACP_DEVICE_SAVE_DATA_SIZE_MAX_OFFSET)[0]
        self.device_save_data_journal_size_max = struct.unpack_from(
            "<Q", data, NACP_DEVICE_SAVE_DATA_JOURNAL_SIZE_MAX_OFFSET)[0]
        self.temporary_storage_size        = struct.unpack_from("<Q", data, NACP_TEMPORARY_STORAGE_SIZE_OFFSET)[0]
        self.cache_storage_size            = struct.unpack_from("<Q", data, NACP_CACHE_STORAGE_SIZE_OFFSET)[0]
        self.cache_storage_journal_size    = struct.unpack_from("<Q", data, NACP_CACHE_STORAGE_JOURNAL_SIZE_OFFSET)[0]
        self.cache_storage_data_and_journal_size_max = struct.unpack_from(
            "<Q", data, NACP_CACHE_STORAGE_DATA_AND_JOURNAL_SIZE_MAX_OFFSET)[0]
        self.play_log_queryable_application_id = struct.unpack_from(
            "<Q", data, NACP_PLAY_LOG_QUERYABLE_APPLICATION_ID_OFFSET)[0]

        # ── 2-byte fields ─────────────────────────────────────────────────
        self.cache_storage_index_max = struct.unpack_from("<H", data, NACP_CACHE_STORAGE_INDEX_MAX_OFFSET)[0]

        # ── Rating ages ───────────────────────────────────────────────────
        self._parse_rating_ages(data)

        # ── Display version ───────────────────────────────────────────────
        self.display_version = self._read_null_terminated_string(
            data, NACP_DISPLAY_VERSION_OFFSET, 0x10
        )

        # ── Application error code category ──────────────────────────────
        self.application_error_code_category = self._read_null_terminated_string(
            data, NACP_APPLICATION_ERROR_CODE_CATEGORY_OFFSET, 0x8
        )

        # ── BCAT passphrase ───────────────────────────────────────────────
        self.bcat_passphrase = self._read_null_terminated_string(
            data, NACP_BCAT_PASSPHRASE_OFFSET, 0x41
        )

    # -----------------------------------------------------------------------
    # Title parsing helpers
    # -----------------------------------------------------------------------

    def _parse_titles_format0(self, data: bytes):
        """
        Parse application titles for Format0 (classic uncompressed layout).

        The first 0x3000 bytes contain 16 ApplicationTitle entries, each 0x300
        bytes, in LanguageCode order.
        """
        self.titles = []
        for lang_idx in range(FORMAT0_LANGUAGE_COUNT):
            offset = NACP_TITLE_OFFSET + lang_idx * APPLICATION_TITLE_SIZE
            name      = self._read_null_terminated_string(data, offset, APPLICATION_NAME_SIZE)
            publisher = self._read_null_terminated_string(
                data, offset + APPLICATION_NAME_SIZE, APPLICATION_PUBLISHER_SIZE)
            self.titles.append(ApplicationTitle(language=lang_idx, name=name, publisher=publisher))

    def _parse_titles_format1(self, data: bytes):
        """
        Parse application titles for Format1 (raw-deflate compressed layout).

        Layout of the first 0x3000 bytes:
          [0x0000] u16 LE  – compressed byte length N
          [0x0002] N bytes – raw deflate stream (zlib wbits=-15)

        The deflate stream decompresses to exactly 0x6000 bytes, containing
        32 ApplicationTitle slots (0x300 bytes each) in LanguageCode order.
        """
        self.titles = []

        compressed_size = struct.unpack_from("<H", data, FORMAT1_COMPRESSED_SIZE_OFFSET)[0]
        compressed_data = data[FORMAT1_COMPRESSED_DATA_OFFSET:
                               FORMAT1_COMPRESSED_DATA_OFFSET + compressed_size]

        try:
            # wbits=-15 → raw deflate (no zlib/gzip wrapper)
            decompressed = zlib.decompress(compressed_data, wbits=-15)
        except zlib.error as exc:
            raise ValueError(
                f"Failed to decompress Format1 title data "
                f"(compressed_size=0x{compressed_size:x}): {exc}"
            ) from exc

        if len(decompressed) < FORMAT1_DECOMPRESSED_SIZE:
            raise ValueError(
                f"Format1 decompressed size too small: "
                f"0x{len(decompressed):x} < 0x{FORMAT1_DECOMPRESSED_SIZE:x}"
            )

        for lang_idx in range(FORMAT1_LANGUAGE_COUNT):
            offset    = lang_idx * APPLICATION_TITLE_SIZE
            name      = self._read_null_terminated_string(decompressed, offset, APPLICATION_NAME_SIZE)
            publisher = self._read_null_terminated_string(
                decompressed, offset + APPLICATION_NAME_SIZE, APPLICATION_PUBLISHER_SIZE)
            self.titles.append(ApplicationTitle(language=lang_idx, name=name, publisher=publisher))

    def _parse_rating_ages(self, data: bytes):
        """Parse rating ages for all 13 organizations."""
        self.rating_ages = []
        for org_idx in range(13):
            offset = NACP_RATING_AGE_OFFSET + org_idx
            age = data[offset]
            try:
                org = OrganizationType(org_idx)
            except ValueError:
                continue
            self.rating_ages.append(RatingAge(organization=org, age=age))

    # -----------------------------------------------------------------------
    # String helper
    # -----------------------------------------------------------------------

    @staticmethod
    def _read_null_terminated_string(data: bytes, offset: int, max_size: int) -> str:
        end = min(offset + max_size, len(data))
        raw = data[offset:end]
        try:
            return raw.split(b"\x00", 1)[0].decode("utf-8")
        except (UnicodeDecodeError, IndexError):
            return ""

    # -----------------------------------------------------------------------
    # Public accessors
    # -----------------------------------------------------------------------

    def get_title_by_language(self, language: LanguageCode) -> Optional[ApplicationTitle]:
        if 0 <= language < len(self.titles):
            return self.titles[language]
        return None

    def get_english_title(self) -> str:
        title = self.get_title_by_language(LanguageCode.AMERICAN_ENGLISH)
        return title.name if title else ""

    def get_english_publisher(self) -> str:
        title = self.get_title_by_language(LanguageCode.AMERICAN_ENGLISH)
        return title.publisher if title else ""

    # -----------------------------------------------------------------------
    # Pretty printer
    # -----------------------------------------------------------------------

    def print_info(self, verbose: bool = False):
        fmt_name = TitlesDataFormat(self.titles_data_format).name if self.titles_data_format in (0, 1) else f"0x{self.titles_data_format:02x}"
        print(f"\n[ApplicationControlProperty]")
        print(f"  TitlesDataFormat:               {fmt_name}")

        # Print application titles
        print(f"  Titles:")
        for title in self.titles:
            if title.name or title.publisher:
                lang_name = LANGUAGE_NAMES.get(title.language, f"Language{title.language}")
                print(f"    [{lang_name}]")
                if title.name:
                    print(f"      Name:      {title.name}")
                if title.publisher:
                    print(f"      Publisher: {title.publisher}")

        if self.isbn:
            print(f"  ISBN:                           {self.isbn}")

        print(f"  StartupUserAccount:             {self._enum_name(StartupUserAccount, self.startup_user_account)}")
        print(f"  UserAccountSwitchLock:          {self._enum_name(UserAccountSwitchLock, self.user_account_switch_lock)}")
        print(f"  AddOnContentRegistrationType:   {self._enum_name(AddOnContentRegistrationType, self.add_on_content_registration_type)}")
        print(f"  Screenshot:                     {self._enum_name(Screenshot, self.screenshot)}")
        print(f"  VideoCapture:                   {self._enum_name(VideoCapture, self.video_capture)}")
        print(f"  DataLossConfirmation:           {self._enum_name(DataLossConfirmation, self.data_loss_confirmation)}")
        print(f"  PlayLogPolicy:                  {self._enum_name(PlayLogPolicy, self.play_log_policy)}")
        print(f"  LogoType:                       {self._enum_name(LogoType, self.logo_type)}")
        print(f"  LogoHandling:                   {self._enum_name(LogoHandling, self.logo_handling)}")
        print(f"  DisplayVersion:                 {self.display_version}")
        print(f"  PresenceGroupId:                0x{self.presence_group_id:016x}")
        print(f"  AddOnContentBaseId:             0x{self.add_on_content_base_id:016x}")
        print(f"  SaveDataOwnerId:                0x{self.save_data_owner_id:016x}")
        print(f"  LocalCommunicationId:           0x{self.local_communication_id:016x}")

        if self.user_account_save_data_size:
            print(f"  UserAccountSaveDataSize:        0x{self.user_account_save_data_size:x}")
        if self.device_save_data_size:
            print(f"  DeviceSaveDataSize:             0x{self.device_save_data_size:x}")
        if self.temporary_storage_size:
            print(f"  TemporaryStorageSize:           0x{self.temporary_storage_size:x}")
        if self.cache_storage_size:
            print(f"  CacheStorageSize:               0x{self.cache_storage_size:x}")

        # Supported languages from bitmask
        if self.supported_language_flag:
            lang_list = []
            for bit in range(32):
                if self.supported_language_flag & (1 << bit):
                    lang_list.append(LANGUAGE_NAMES.get(bit, f"Language{bit}"))
            if lang_list:
                print(f"  SupportedLanguages:             {', '.join(lang_list)}")

        # Rating ages
        has_ratings = False
        for rating in self.rating_ages:
            if 0 < rating.age < 255:
                if not has_ratings:
                    print(f"  Ratings:")
                    has_ratings = True
                org_name = OrganizationType(rating.organization).name
                print(f"    {org_name}: {rating.age}")

        if verbose:
            print(f"  AttributeFlag:                  0x{self.attribute_flag:08x}")
            print(f"  SupportedLanguageFlag:          0x{self.supported_language_flag:08x}")
            print(f"  ParentalControlFlag:            0x{self.parental_control_flag:08x}")
            print(f"  RuntimeAddOnContentInstall:     {self._enum_name(RuntimeAddOnContentInstall, self.runtime_add_on_content_install)}")
            print(f"  RuntimeParameterDelivery:       {self._enum_name(RuntimeParameterDelivery, self.runtime_parameter_delivery)}")
            print(f"  AppropriateAgeForChina:         {self._enum_name(AppropriateAgeForChina, self.appropriate_age_for_china)}")
            print(f"  CrashReport:                    {self._enum_name(CrashReport, self.crash_report)}")
            print(f"  Hdcp:                           {self._enum_name(Hdcp, self.hdcp)}")
            print(f"  PlayLogQueryCapability:         {self._enum_name(PlayLogQueryCapability, self.play_log_query_capability)}")
            print(f"  ApparentPlatform:               {self._enum_name(ApparentPlatform, self.apparent_platform)}")
            if self.bcat_passphrase:
                print(f"  BcatPassphrase:                 {self.bcat_passphrase[:16]}...")

    @staticmethod
    def _enum_name(enum_class, value: int) -> str:
        try:
            return enum_class(value).name
        except ValueError:
            return f"Unknown(0x{value:02x})"

    def __repr__(self):
        english_title = self.get_english_title()
        return f"NACP(title={english_title[:30] if english_title else 'Unknown'})"


# ============================================================================
# Convenience function
# ============================================================================

def parse_nacp(data: bytes) -> NACP:
    """
    Convenience function to parse NACP data.

    Args:
        data: Complete NACP binary data (0x4000 bytes)

    Returns:
        Parsed NACP object
    """
    nacp = NACP()
    nacp.parse(data)
    return nacp


# Example usage:
# with open("control.nacp", "rb") as f:
#     data = f.read()
#     nacp = parse_nacp(data)
#     nacp.print_info(verbose=True)
#     print(f"Title: {nacp.get_english_title()}")