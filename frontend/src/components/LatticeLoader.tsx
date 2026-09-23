const latticeCells = Array.from({ length: 25 }, (_, index) => index)

export default function LatticeLoader() {
  return (
    <div className="lattice-loader" role="status" aria-label="Thinking">
      <div className="lattice-loader__grid" aria-hidden="true">
        {latticeCells.map((cell) => (
          <span key={cell} />
        ))}
      </div>
      <p className="lattice-loader__label">Thinking...</p>
    </div>
  )
}
