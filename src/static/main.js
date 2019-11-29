mapboxgl.accessToken =
  "pk.eyJ1IjoicHl0aG9uMjczIiwiYSI6ImNrM2pyaHE5cjBraG4zbm9jM25naHcwdWIifQ.QuT8LlWCOphbeef4cO2QYw";
var map = new mapboxgl.Map({
  container: "map",
  style: "mapbox://styles/mapbox/dark-v10",
  center: [0, 25],
  zoom: 1.6,
  antialias: true
});
window.map = map;
map.addControl(new mapboxgl.NavigationControl());

map.on("load", function() {
  const addedIps = {};
  const data = {
    type: "FeatureCollection",
    features: []
  };
  map.addSource("mypoints", { type: "geojson", data: data });

  var mySource = map.getSource("mypoints");
  const addPoint = (lat, lon) => {
    data["features"].push({
      type: "Feature",
      properties: {},
      geometry: {
        type: "Point",
        coordinates: [lon, lat]
      }
    });
    mySource.setData(data);
  };

  const ws = new WebSocket("ws://" + window.location.host + "/ws");
  ws.addEventListener("message", event => {
    const data = JSON.parse(event.data);

    if (data.ipSrcLatitude && data.ipSrcLongitude) {
      if (addedIps[data.ipSrc] !== 1) {
        addedIps[data.ipSrc] = 1;
        addPoint(data.ipSrcLatitude, data.ipSrcLongitude);
      }

      addPointAnimation(data, "src");
    }

    if (data.ipDstLatitude && data.ipDstLongitude) {
      if (addedIps[data.ipDst] !== 1) {
        addedIps[data.ipDst] = 1;
        addPoint(data.ipDstLatitude, data.ipDstLongitude);
      }

      addPointAnimation(data, "dst");
    }
  });

  map.addLayer({
    id: "mylayer",
    type: "circle",
    source: "mypoints",
    paint: {
      "circle-radius": {
        base: 25,
        stops: [
          [12, 4],
          [22, 180]
        ]
      },
      "circle-color": "#aa0000",
      "circle-blur": 0.2
    }
  });
});

// ---

var THREE = window.THREE;

var myMaterial = new THREE.ShaderMaterial({
  uniforms: {
    some: { type: "f", value: 0.0 },
    color: new THREE.Uniform(new THREE.Color())
  },
  vertexShader: `
  varying vec2 vUv;

  void main() 
  {
    vUv = uv;
    vec4 modelViewPosition = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * modelViewPosition;
  }
  `,
  fragmentShader: `
  varying vec2 vUv;
  uniform float some;
  uniform vec3 color;

  void main() {
    float t = some / 6.0;
    float d = distance(vUv, vec2(0.5, 0.5));

    gl_FragColor = vec4(0.0, 0.0, 0.0, 0.0);
    if (d < t && d > (t - 0.03) && d < 0.5) {
      gl_FragColor = vec4(color, 0.5);
    }
  }      
  `
});
let scene;

var startTime = Date.now();

function updateFromData(obj, data, srcdst) {
  let lat, lon;

  if (srcdst === "src") {
    lat = data.ipSrcLatitude;
    lon = data.ipSrcLongitude;
    obj.material.uniforms.color.value.setHSL(0.5, 1.0, 0.5);
  } else {
    lat = data.ipDstLatitude;
    lon = data.ipDstLongitude;
    obj.material.uniforms.color.value.setHSL(0.0, 1.0, 0.5);
  }

  var modelAsMercatorCoordinate = mapboxgl.MercatorCoordinate.fromLngLat(
    [lon, lat],
    0 // Altitude
  );
  obj.position.set(
    modelAsMercatorCoordinate.x,
    modelAsMercatorCoordinate.y,
    modelAsMercatorCoordinate.z
  );

  obj.userData.sentAt = new Date(data.ts * 1000.0);
}

function createPoint(...args) {
  const geometry = new THREE.PlaneGeometry(1, 1, 1);

  geometry.rotateX(Math.PI); // to make frontside
  geometry.scale(0.03, 0.03, 0.03);

  const plane = new THREE.Mesh(geometry, myMaterial.clone());

  updateFromData(plane, ...args);

  return plane;
}

let reusePool = [];

function addPointAnimation(...args) {
  if (!scene) {
    return;
  }

  let point = reusePool.pop();

  if (point) {
    updateFromData(point, ...args);
  } else {
    scene.add(createPoint(...args));
  }
}

var customLayer = {
  id: "3d-model",
  type: "custom",
  renderingMode: "2d",
  onAdd: function(map, gl) {
    this.camera = new THREE.Camera();
    this.scene = new THREE.Scene();
    scene = this.scene;

    this.map = map;

    this.renderer = new THREE.WebGLRenderer({
      canvas: map.getCanvas(),
      context: gl,
      antialias: true
    });
    this.renderer.autoClear = false;
  },
  render: function(gl, matrix) {
    this.camera.projectionMatrix = new THREE.Matrix4().fromArray(matrix);

    const d = new Date();

    for (let mesh of this.scene.children) {
      let newVal = new Number(d - mesh.userData.sentAt) / 1000.0;
      mesh.material.uniforms.some.value = newVal;
      if (newVal > 6.0) {
        reusePool.push(mesh);
      }
    }

    this.renderer.state.reset();
    this.renderer.render(this.scene, this.camera);
    this.map.triggerRepaint();
  }
};

map.on("style.load", function() {
  map.addLayer(customLayer, "waterway-label");
});

setInterval(() => {
  if (!scene) {
    return;
  }

  console.log("animating", scene.children.length);
}, 1000);
