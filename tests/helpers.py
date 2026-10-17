from aem.models import OrgProfile


def make_org(detections=(), entries=(), default_asset="ws", **extra) -> OrgProfile:
    data = {
        "organization": "Org Ficticia de Prueba",
        "assets": [
            {"id": "web", "name": "Portal", "criticality": "alta", "processes_regulated_data": True, "exposure": "internet"},
            {"id": "ws", "name": "Estaciones", "criticality": "media", "processes_regulated_data": False, "exposure": "interna"},
            {"id": "lab", "name": "Laboratorio", "criticality": "baja", "processes_regulated_data": False, "exposure": "aislada"},
        ],
        "data_sources": [{"name": "Process Creation", "quality": 4}, {"name": "Logon Session", "quality": 3}],
        "detections": [dict(technique_id=t, score=s, data_sources=ds) for t, s, ds in detections],
        "analyst_context": {"default_asset_id": default_asset,
                            "entries": [dict(technique_id=t, asset_id=a) for t, a in entries]},
    }
    data.update(extra)
    return OrgProfile.model_validate(data)
