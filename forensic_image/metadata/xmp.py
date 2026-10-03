"""Forensic XMP metadata extraction and history sequence analysis using defusedxml."""

from typing import Any, Dict, List, Optional
import defusedxml.ElementTree as ET
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus


class XMPHistoryEvent(BaseModel):
    """A documented historical edit or state transition from xmpMM:History."""
    action: Optional[str] = None
    instance_id: Optional[str] = None
    timestamp: Optional[str] = None
    software_agent: Optional[str] = None
    parameters: Optional[str] = None
    changed: Optional[str] = None


class XMPData(BaseModel):
    """Structured XMP forensic metadata container."""
    is_present: bool = False
    status: FindingStatus = FindingStatus.NOT_AVAILABLE
    creator_tool: Optional[str] = None
    create_date: Optional[str] = None
    modify_date: Optional[str] = None
    metadata_date: Optional[str] = None
    document_id: Optional[str] = None
    instance_id: Optional[str] = None
    original_document_id: Optional[str] = None
    format: Optional[str] = None
    creator: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    history: List[XMPHistoryEvent] = Field(default_factory=list)
    raw_namespaces: Dict[str, str] = Field(default_factory=dict)
    raw_properties: Dict[str, str] = Field(default_factory=dict)


class XMPParser:
    """Safe, defensive XMP parser immune to XML Entity Expansion (XXE) and billion laughs attacks."""

    NAMESPACES = {
        "x": "adobe:ns:meta/",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "xmp": "http://ns.adobe.com/xap/1.0/",
        "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
        "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
        "dc": "http://purl.org/dc/elements/1.1/",
        "photoshop": "http://ns.adobe.com/photoshop/1.0/",
        "crs": "http://ns.adobe.com/camera-raw-settings/1.0/",
    }

    def parse(self, xmp_bytes_or_str: Any) -> XMPData:
        result = XMPData()
        if not xmp_bytes_or_str:
            return result

        if isinstance(xmp_bytes_or_str, bytes):
            # Strip standard XMP packet headers <?xpacket begin=...
            text = xmp_bytes_or_str.decode("utf-8", errors="replace")
        else:
            text = str(xmp_bytes_or_str)

        # Locate rdf:RDF root if enclosed in packet wrappers
        rdf_start = text.find("<rdf:RDF")
        rdf_end = text.find("</rdf:RDF>")
        if rdf_start != -1 and rdf_end != -1:
            xml_clean = text[rdf_start : rdf_end + 10]
        else:
            xml_clean = text

        try:
            root = ET.fromstring(xml_clean)
        except Exception:
            return result

        result.is_present = True
        result.status = FindingStatus.OBSERVED

        # Walk elements and extract tags
        for elem in root.iter():
            tag = elem.tag
            # Remove namespace URI prefix {http://...}
            tag_name = tag.split("}")[-1] if "}" in tag else tag
            val = elem.text.strip() if elem.text else None

            # Capture direct attributes if present
            for attr_key, attr_val in elem.attrib.items():
                attr_name = attr_key.split("}")[-1] if "}" in attr_key else attr_key
                self._map_field(result, attr_name, attr_val)

            if val:
                result.raw_properties[tag_name] = val
                self._map_field(result, tag_name, val)

            # Check for xmpMM:History ResourceEvents
            if tag.endswith("ResourceEvent") or tag_name == "ResourceEvent" or tag_name == "li":
                self._parse_history_event(elem, result)

        return result

    def _map_field(self, data: XMPData, key: str, val: str) -> None:
        if not val:
            return
        k = key.lower()
        if k in ("creatortool", "xmp:creatortool"):
            data.creator_tool = val
        elif k in ("createdate", "xmp:createdate"):
            data.create_date = val
        elif k in ("modifydate", "xmp:modifydate"):
            data.modify_date = val
        elif k in ("metadatadate", "xmp:metadatadate"):
            data.metadata_date = val
        elif k in ("documentid", "xmpmm:documentid"):
            data.document_id = val
        elif k in ("instanceid", "xmpmm:instanceid"):
            data.instance_id = val
        elif k in ("originaldocumentid", "xmpmm:originaldocumentid"):
            data.original_document_id = val
        elif k in ("format", "dc:format"):
            data.format = val
        elif k in ("creator", "dc:creator"):
            data.creator = val
        elif k in ("title", "dc:title"):
            data.title = val
        elif k in ("description", "dc:description"):
            data.description = val

    def _parse_history_event(self, elem: Any, data: XMPData) -> None:
        event = XMPHistoryEvent()
        found = False
        # Look for attributes
        for k, v in elem.attrib.items():
            name = k.split("}")[-1] if "}" in k else k
            if name == "action":
                event.action = v
                found = True
            elif name == "instanceID":
                event.instance_id = v
                found = True
            elif name == "when":
                event.timestamp = v
                found = True
            elif name == "softwareAgent":
                event.software_agent = v
                found = True
            elif name == "parameters":
                event.parameters = v
                found = True
            elif name == "changed":
                event.changed = v
                found = True

        # Look for sub-elements
        for child in elem:
            name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            txt = child.text.strip() if child.text else None
            if not txt:
                continue
            if name == "action":
                event.action = txt
                found = True
            elif name == "instanceID":
                event.instance_id = txt
                found = True
            elif name == "when":
                event.timestamp = txt
                found = True
            elif name == "softwareAgent":
                event.software_agent = txt
                found = True
            elif name == "parameters":
                event.parameters = txt
                found = True
            elif name == "changed":
                event.changed = txt
                found = True

        if found:
            data.history.append(event)
