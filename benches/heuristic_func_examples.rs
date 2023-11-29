// EXAMPLE 1 (custom ChatGPT heuristic func)
use std::mem;

// Assuming each hash value is 32 bytes (adjust based on your use case)
const HASH_SIZE_BYTES: usize = 32;

// Heuristic function to estimate memory usage for a Merkle Tree
fn estimate_memory_usage(height: u32, num_nodes: u32) -> usize {
    // Calculate the number of hash values in the Merkle Tree
    let num_hash_values = 2u32.pow(height);

    // Calculate the total memory usage
    let memory_usage_bytes =
        num_nodes as usize * HASH_SIZE_BYTES + num_hash_values as usize * mem::size_of::<u8>();

    memory_usage_bytes
}

// main func
fn calculate() {
    // Example usage
    let tree_height = 4; // Replace with your desired height
    let num_nodes = 15; // Replace with your desired number of nodes

    let estimated_memory_usage = estimate_memory_usage(tree_height, num_nodes);

    println!(
        "Estimated memory usage for a Merkle Tree of height {} with {} nodes: {} bytes",
        tree_height, num_nodes, estimated_memory_usage
    );
}

// EXAMPLE 2

// This Python code to Rust:
// https://stackoverflow.com/a/44315221

use plotters::prelude::*;
use rand::Rng;

const N_POINTS: usize = 10;
const TARGET_X_SLOPE: f64 = 2.0;
const TARGET_Y_SLOPE: f64 = 3.0;
const TARGET_OFFSET: f64 = 5.0;
const EXTENTS: f64 = 5.0;
const NOISE: f64 = 5.0;

// main func
fn plot1() {
    // Create random data
    let mut rng = rand::thread_rng();
    let xs: Vec<f64> = (0..N_POINTS)
        .map(|_| rng.gen_range(-EXTENTS..EXTENTS))
        .collect();
    let ys: Vec<f64> = (0..N_POINTS)
        .map(|_| rng.gen_range(-EXTENTS..EXTENTS))
        .collect();
    let zs: Vec<f64> = xs
        .iter()
        .zip(ys.iter())
        .map(|(&x, &y)| {
            x * TARGET_X_SLOPE + y * TARGET_Y_SLOPE + TARGET_OFFSET + rng.gen_range(-NOISE..NOISE)
        })
        .collect();

    // Plot raw data
    let root = BitMapBackend::new("scatter_plot.png", (800, 600)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let mut chart = ChartBuilder::on(&root)
        .caption("3D Scatter Plot", ("sans-serif", 20))
        .build_cartesian_3d(-EXTENTS..EXTENTS, -EXTENTS..EXTENTS, -EXTENTS..EXTENTS)
        .unwrap();

    chart.configure_axes().draw().unwrap();
    chart
        .draw_series(SurfaceSeries::xoz(
            xs.iter()
                .zip(ys.iter())
                .zip(zs.iter())
                .map(|((x, y), z)| (*x, *z, *y)),
            &BLUE.mix(0.5),
        ))
        .unwrap();

    // Perform the fit
    let tmp_a: Vec<Vec<f64>> = xs
        .iter()
        .zip(ys.iter())
        .map(|(&x, &y)| vec![x, y, 1.0])
        .collect();
    let tmp_b: Vec<f64> = zs.iter().copied().collect();
    let b = Matrix::new_column_vec(&tmp_b);
    let a = Matrix::new(tmp_a);
    let fit = a.clone().transpose() * &a;
    let fit = fit.invert().unwrap() * a.transpose() * b;
    let errors = &b - &a * &fit;
    let residual = errors.norm();

    // Print the results
    println!("solution:");
    println!("{}x + {}y + {} = z", fit[(0, 0)], fit[(1, 0)], fit[(2, 0)]);
    println!("errors:");
    println!("{:?}", errors);
    println!("residual:");
    println!("{}", residual);

    // Plot the plane
    let mut chart = ChartBuilder::on(&root)
        .caption("Fitted Plane", ("sans-serif", 20))
        .build_cartesian_3d(-EXTENTS..EXTENTS, -EXTENTS..EXTENTS, -EXTENTS..EXTENTS)
        .unwrap();

    chart.configure_axes().draw().unwrap();
    chart
        .draw_series(SurfaceSeries::xz(
            (0..100).map(|i| -EXTENTS + 2.0 * EXTENTS * i as f64 / 100.0),
            (0..100).map(|i| -EXTENTS + 2.0 * EXTENTS * i as f64 / 100.0),
            |x, z| fit[(0, 0)] * x + fit[(2, 0)] * z + fit[(1, 0)],
            &BLACK.mix(0.5),
        ))
        .unwrap();
}

// EXAMPLE 3

// This Python code to Rust:
// https://scikit-spatial.readthedocs.io/en/stable/gallery/fitting/plot_plane.html

use nalgebra::{Matrix3, Vector3};
use plotters::prelude::*;

// main func
fn plot2() {
    // Define points
    let points = vec![
        Vector3::new(0.0, 0.0, 0.0),
        Vector3::new(1.0, 3.0, 5.0),
        Vector3::new(-5.0, 6.0, 3.0),
        Vector3::new(3.0, 6.0, 7.0),
        Vector3::new(-2.0, 6.0, 7.0),
    ];

    // Find the best-fit plane
    let plane = best_fit_plane(&points);

    // Plot 3D points and the plane
    plot_3d(points, plane);
}

fn best_fit_plane(points: &Vec<Vector3<f64>>) -> (Vector3<f64>, Vector3<f64>) {
    let centroid = compute_centroid(points);
    let centered_points: Vec<Vector3<f64>> = points.iter().map(|p| p - centroid).collect();

    let covariance_matrix = compute_covariance_matrix(&centered_points);
    let eigenvectors = covariance_matrix.symmetric_eigen().eigenvalues;
    let normal = eigenvectors.column(0);

    (centroid, normal)
}

fn compute_centroid(points: &Vec<Vector3<f64>>) -> Vector3<f64> {
    points.iter().fold(Vector3::zeros(), |acc, &p| acc + p) / points.len() as f64
}

fn compute_covariance_matrix(points: &Vec<Vector3<f64>>) -> Matrix3<f64> {
    let n = points.len() as f64;
    let centroid = compute_centroid(points);

    let mut covariance_matrix = Matrix3::zeros();

    for p in points {
        let centered_point = p - centroid;
        covariance_matrix += centered_point * centered_point.transpose();
    }

    covariance_matrix /= n;

    covariance_matrix
}

fn plot_3d(points: Vec<Vector3<f64>>, plane: (Vector3<f64>, Vector3<f64>)) {
    let root = BitMapBackend::new("3d_plot.png", (800, 600)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let mut chart = ChartBuilder::on(&root)
        .caption("3D Plot", ("sans-serif", 20))
        .build_cartesian_3d(-10.0..10.0, -10.0..10.0, -10.0..10.0)
        .unwrap();

    chart.configure_axes().draw().unwrap();

    // Plot 3D points
    chart
        .draw_series(points.iter().map(|p| {
            return Circle::new((*p.x as i32, *p.y as i32), 5, ShapeStyle::from(&BLACK));
        }))
        .unwrap();

    // Plot the best-fit plane
    let normal = plane.1;
    let d = -normal.dot(&plane.0);
    let plane_points = (0..100)
        .flat_map(|i| (0..100).map(move |j| (i as f64 - 50.0, j as f64 - 50.0)))
        .map(|(i, j)| {
            let k = -(normal.x * i + normal.y * j + d) / normal.z;
            (i, j, k)
        });

    chart
        .draw_series(SurfaceSeries::new(plane_points, 100, &WHITE.mix(0.5)))
        .unwrap();
}

// EXAMPLE 4

// This Python code to Rust
// https://math.stackexchange.com/a/99317

use nalgebra::{Matrix3, Vector3, U2};

// main func
fn get_plane() {
    // Generate some random test points
    let m = 20; // number of points
    let delta = 0.01; // size of random displacement
    let origin = Vector3::new(rand::random(), rand::random(), rand::random()); // random origin for the plane
    let basis = Matrix3::from_fn(|_, _| rand::random()); // random basis vectors for the plane
    let coefficients = Matrix3::from_fn(|_, _| rand::random()); // random coefficients for points on the plane

    // Generate random points on the plane and add random displacement
    let points = basis * coefficients + origin.broadcast(m);

    // Now find the best-fitting plane for the test points

    // Subtract out the centroid and take the SVD
    let centroid = points.column_mean();
    let centered_points = points - centroid.broadcast(m);
    let svd = centered_points.svd(true, true);

    // Extract the left singular vectors
    let left = svd.u.unwrap();

    // Print the left singular vectors
    println!("Left singular vectors:\n{}", left);
}

// DEPENDENCIES (for exx. 2, 3 and 4)

// [dependencies]
// plotters = "0.5" // exx. 2 and 3
// rand = "0.8" // ex. 2
// nalgebra = "0.29" // exx. 3 and 4
