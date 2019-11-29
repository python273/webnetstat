mapboxgl.accessToken = 'pk.eyJ1IjoicHl0aG9uMjczIiwiYSI6ImNrM2pyaHE5cjBraG4zbm9jM25naHcwdWIifQ.QuT8LlWCOphbeef4cO2QYw';
var map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/mapbox/dark-v10',
    center: [0, 25],
    zoom: 1.6,
});
map.addControl(new mapboxgl.NavigationControl());

map.on('load', function () {
    const addedIps = {};
    const data = {
        "type": "FeatureCollection",
        "features": []
    };
    map.addSource('mypoints', { type: 'geojson', data: data});

    var mySource = map.getSource('mypoints');
    const addPoint = (lat, lon) => {
        data['features'].push({
            "type": "Feature",
            "properties": {},
            "geometry": {
                "type": "Point",
                "coordinates": [lon, lat]
            }
        })
        mySource.setData(data);
    };

    const ws = new WebSocket("ws://" + window.location.host + "/ws")
    ws.addEventListener('message', (event) => {
        const data = JSON.parse(event.data);

        if (data.ipSrcLatitude && data.ipSrcLongitude) {
            if (addedIps[data.ipSrc] !== 1) {
                addedIps[data.ipSrc] = 1;
                addPoint(data.ipSrcLatitude, data.ipSrcLongitude);
            }
        }

        if (data.ipDstLatitude && data.ipDstLongitude) {
            if (addedIps[data.ipDst] !== 1) {
                addedIps[data.ipDst] = 1;
                addPoint(data.ipDstLatitude, data.ipDstLongitude);
            }
        }
    });

    map.addLayer({
        'id': 'mylayer',
        'type': 'circle',
        'source': 'mypoints',
        'paint': {
            'circle-radius': {
                'base': 25,
                'stops': [[12, 4], [22, 180]]
            },
            "circle-color": "#ff0000",
            "circle-blur": 0.2,
        }
    });
});
