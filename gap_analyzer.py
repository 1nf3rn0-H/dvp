def compute_visibility_gaps(event):
    gaps = []
    matrix = event.get("visibility_matrix", {})
    for layer, visible in matrix.items():
        if visible is False:
            gaps.append(layer)
    return gaps