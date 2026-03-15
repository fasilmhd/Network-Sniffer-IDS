import os
import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any


class FileHandler:
    """Export packet data in CSV, JSON, or XML formats."""

    @staticmethod
    def export_to_csv(
        packets: List[Dict[str, Any]],
        filename: str,
        include_headers: bool = True,
        include_payload: bool = False
    ) -> bool:
        """Write packet list to a CSV file."""
        try:
            os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
            fieldnames = ["packet_num", "timestamp", "src_ip", "dst_ip",
                          "protocol", "length", "info"]
            if include_payload:
                fieldnames.append("payload")

            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if include_headers:
                    writer.writeheader()
                for idx, pkt in enumerate(packets, start=1):
                    row = {
                        "packet_num": idx,
                        "timestamp": pkt.get("timestamp", ""),
                        "src_ip": pkt.get("src_ip", ""),
                        "dst_ip": pkt.get("dst_ip", ""),
                        "protocol": pkt.get("protocol", ""),
                        "length": pkt.get("length", 0),
                        "info": pkt.get("info", ""),
                    }
                    if include_payload:
                        row["payload"] = pkt.get("payload", "")
                    writer.writerow(row)
            return True
        except Exception:
            return False

    @staticmethod
    def export_to_json(
        packets: List[Dict[str, Any]],
        filename: str,
        include_payload: bool = False
    ) -> bool:
        """Write packet list to a JSON file with metadata."""
        try:
            os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
            export_data = {
                "export_info": {
                    "timestamp": datetime.now().isoformat(),
                    "packet_count": len(packets),
                    "include_payload": include_payload
                },
                "packets": []
            }
            for idx, pkt in enumerate(packets, start=1):
                entry = {
                    "packet_num": idx,
                    "timestamp": pkt.get("timestamp", ""),
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "protocol": pkt.get("protocol", ""),
                    "length": pkt.get("length", 0),
                    "info": pkt.get("info", "")
                }
                if include_payload:
                    entry["payload"] = pkt.get("payload", "")
                export_data["packets"].append(entry)

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    @staticmethod
    def export_to_xml(
        packets: List[Dict[str, Any]],
        filename: str,
        include_payload: bool = False
    ) -> bool:
        """Write packet list to an XML file with metadata."""
        try:
            os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
            root = ET.Element("packet_capture")
            meta = ET.SubElement(root, "metadata")
            ET.SubElement(meta, "timestamp").text = datetime.now().isoformat()
            ET.SubElement(meta, "packet_count").text = str(len(packets))
            ET.SubElement(meta, "include_payload").text = str(include_payload)

            packets_elem = ET.SubElement(root, "packets")
            for idx, pkt in enumerate(packets, start=1):
                pkt_elem = ET.SubElement(packets_elem, "packet", number=str(idx))
                ET.SubElement(pkt_elem, "timestamp").text = pkt.get("timestamp", "")
                ET.SubElement(pkt_elem, "src_ip").text = pkt.get("src_ip", "")
                ET.SubElement(pkt_elem, "dst_ip").text = pkt.get("dst_ip", "")
                ET.SubElement(pkt_elem, "protocol").text = pkt.get("protocol", "")
                ET.SubElement(pkt_elem, "length").text = str(pkt.get("length", 0))
                ET.SubElement(pkt_elem, "info").text = pkt.get("info", "")
                if include_payload:
                    ET.SubElement(pkt_elem, "payload").text = pkt.get("payload", "")

            tree = ET.ElementTree(root)
            tree.write(filename, encoding="utf-8", xml_declaration=True)
            return True
        except Exception:
            return False