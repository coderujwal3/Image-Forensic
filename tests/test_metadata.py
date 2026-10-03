"""Unit tests for EXIF, GPS, XMP, IPTC, ICC, and thumbnail extraction."""

from tests.conftest import build_exif_with_gps, create_test_image
from forensic_image.core.constants import FindingStatus
from forensic_image.metadata.exif import EXIFParser
from forensic_image.metadata.icc import ICCParser
from forensic_image.metadata.iptc import IPTCParser
from forensic_image.metadata.thumbnail import ThumbnailForensics
from forensic_image.metadata.xmp import XMPParser


def test_exif_and_gps_parser() -> None:
    tiff_data = build_exif_with_gps()
    parser = EXIFParser()
    data = parser.parse(tiff_data)

    assert data.is_present is True
    assert data.status == FindingStatus.OBSERVED
    assert data.make == "Nikon Corporation"
    assert data.model == "NIKON D850"
    assert data.software == "Ver.1.10"
    assert data.date_time_original == "2026:05:14 12:30:00"

    # GPS coordinates verification
    assert data.gps.has_coordinates is True
    assert round(data.gps.latitude, 3) == 37.775
    assert round(data.gps.longitude, 3) == -122.420


def test_xmp_parser_with_history() -> None:
    xmp_sample = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
    xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"
    xmlns:dc="http://purl.org/dc/elements/1.1/">
   <xmp:CreatorTool>Adobe Photoshop 2026</xmp:CreatorTool>
   <xmp:CreateDate>2026-01-15T10:00:00Z</xmp:CreateDate>
   <dc:creator>Forensic Specialist</dc:creator>
   <xmpMM:History>
    <rdf:Seq>
     <rdf:li stEvt:action="created" stEvt:when="2026-01-15T10:00:00Z" stEvt:softwareAgent="Adobe Camera Raw"/>
     <rdf:li stEvt:action="saved" stEvt:when="2026-01-15T11:20:00Z" stEvt:softwareAgent="Adobe Photoshop 2026"/>
    </rdf:Seq>
   </xmpMM:History>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

    parser = XMPParser()
    xmp = parser.parse(xmp_sample)

    assert xmp.is_present is True
    assert xmp.creator_tool == "Adobe Photoshop 2026"
    assert xmp.creator == "Forensic Specialist"
    assert len(xmp.history) == 2
    assert xmp.history[0].action == "created"
    assert xmp.history[1].action == "saved"
    assert xmp.history[1].software_agent == "Adobe Photoshop 2026"


def test_iptc_parser() -> None:
    # 8BIM block with resource 0x0404 (IPTC-NAA)
    # IPTC tag 0x1C, 0x02, 0x69 (Headline)
    import struct
    headline = b"Breaking News"
    iptc_payload = b"\x1C\x02\x69" + struct.pack(">H", len(headline)) + headline
    
    # 8BIM wrapper
    b8 = io_8bim = io_buf = bytearray()
    io_buf.extend(b"Photoshop 3.0\x00")
    io_buf.extend(b"8BIM")
    io_buf.extend(struct.pack(">H", 0x0404))  # IPTC resource
    io_buf.extend(b"\x00\x00")  # name len 0 + 1 pad
    io_buf.extend(struct.pack(">I", len(iptc_payload)))
    io_buf.extend(iptc_payload)

    parser = IPTCParser()
    iptc = parser.parse(bytes(io_buf))

    assert iptc.is_present is True
    assert iptc.headline == "Breaking News"


def test_thumbnail_forensics_discrepancy() -> None:
    main_img = create_test_image(1920, 1080, "blue")  # 16:9
    thumb_img = create_test_image(160, 120, "red")    # 4:3 (different AR and different color!)

    import io
    t_buf = io.BytesIO()
    thumb_img.save(t_buf, format="JPEG")
    thumb_bytes = t_buf.getvalue()

    forensics = ThumbnailForensics()
    details, findings = forensics.analyze(thumb_bytes, main_img)

    assert details.is_present is True
    assert details.width == 160
    assert details.height == 120
    assert details.has_discrepancy is True
    assert any("Aspect ratio mismatch" in r for r in details.discrepancy_reasons)
